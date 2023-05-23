# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""OSV API server implementation."""

import argparse
import codecs
import concurrent
import math
import hashlib
import functools
import logging
import os
import time
from typing import List

from collections import defaultdict

from google.cloud import ndb

import grpc
from grpc_reflection.v1alpha import reflection
from packageurl import PackageURL

import osv
from osv import ecosystems
from osv import semver_index
from osv.logs import setup_gcp_logging
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

_MAX_REQUEST_DURATION_SECS = 60
_SHUTDOWN_GRACE_DURATION = 5

_MAX_BATCH_QUERY = 1000
_MAX_VULNERABILITIES_LISTED = 16

# Used in DetermineVersion
# If there are more results for a bucket than this number,
# ignore the bucket completely
_MAX_MATCHES_TO_CARE = 100
# Max results to return for DetermineVersion
_MAX_DETERMINE_VER_RESULTS_TO_RETURN = 10
_DETERMINE_VER_MIN_SCORE_CUTOFF = 0.2
# Size of buckets to divide hashes into in DetermineVersion
# This should match the number in the indexer
_BUCKET_SIZE = 512

_ndb_client = ndb.Client()


def ndb_context(func):
  """Wrapper to create an NDB context."""

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    with _ndb_client.context():
      return func(*args, **kwargs)

  return wrapper


class OSVServicer(osv_service_v1_pb2_grpc.OSVServicer):
  """V1 OSV servicer."""

  @ndb_context
  def GetVulnById(self, request, context: grpc.ServicerContext):
    """Return a `Vulnerability` object for a given OSV ID."""
    bug = osv.Bug.get_by_id(request.id)
    if not bug or bug.status == osv.BugStatus.UNPROCESSED:
      context.abort(grpc.StatusCode.NOT_FOUND, 'Bug not found.')
      return None

    if not bug.public:
      context.abort(grpc.StatusCode.PERMISSION_DENIED, 'Permission denied.')
      return None

    return bug_to_response(bug)

  @ndb_context
  def QueryAffected(self, request, context: grpc.ServicerContext):
    """Query vulnerabilities for a particular project at a given commit or

    version.
    """
    results, next_page_token = do_query(request.query, context).result()
    if results is not None:
      return osv_service_v1_pb2.VulnerabilityList(
          vulns=results, next_page_token=next_page_token)

    return None

  @ndb_context
  def QueryAffectedBatch(self, request, context: grpc.ServicerContext):
    """Query vulnerabilities (batch)."""
    batch_results = []
    futures = []

    if len(request.query.queries) > _MAX_BATCH_QUERY:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Too many queries.')
      return None

    for query in request.query.queries:
      futures.append(do_query(query, context, include_details=False))

    for future in futures:
      batch_results.append(
          osv_service_v1_pb2.VulnerabilityList(vulns=future.result()[0] or []))

    return osv_service_v1_pb2.BatchVulnerabilityList(results=batch_results)

  @ndb_context
  def DetermineVersion(self, request, context: grpc.ServicerContext):
    """Determine the version of the provided hashes."""
    res = determine_version(request.query, context).result()
    return res


def process_buckets(
    file_results: List[osv.FileResult]) -> List[osv.RepoIndexBucket]:
  """
  Create buckets in the same process as 
  indexer to generate the same bucket hashes
  """
  buckets: list[list[bytes]] = [[] for _ in range(_BUCKET_SIZE)]

  for fr in file_results:
    buckets[int.from_bytes(fr.hash[:2], byteorder='big') % _BUCKET_SIZE].append(
        fr.hash)

  results: list[osv.RepoIndexBucket] = [None] * _BUCKET_SIZE
  for bucket_idx, bucket in enumerate(buckets):
    bucket.sort()

    hasher = hashlib.md5()
    for v in bucket:
      hasher.update(v)

    results[bucket_idx] = osv.RepoIndexBucket(
        node_hash=hasher.digest(),
        files_contained=len(bucket),
    )

  return results


def build_determine_version_result(
    file_matches_by_proj: dict[ndb.Key, int],
    bucket_matches_by_proj: dict[ndb.Key, int],
    num_skipped_buckets: int,
    # 1 means has items, 0 means empty
    empty_bucket_bitmap: int,
    max_files: int) -> osv_service_v1_pb2.VersionMatchList:
  """Build sorted determine version result from the input"""
  bucket_match_items = list(bucket_matches_by_proj.items())
  # Sort by number of files matched
  bucket_match_items.sort(key=lambda x: x[1], reverse=True)
  # Only interested in our maximum number of results
  bucket_match_items = bucket_match_items[:min(
      _MAX_DETERMINE_VER_RESULTS_TO_RETURN, len(bucket_match_items))]
  idx_futures = ndb.get_multi_async([b[0] for b in bucket_match_items])
  output = []

  # Apply bitwise NOT to the user bitmap
  inverted_empty_bucket_bitmap = (1 << _BUCKET_SIZE) - 1 - empty_bucket_bitmap
  empty_bucket_count = inverted_empty_bucket_bitmap.bit_count()

  for f in idx_futures:
    idx: osv.RepoIndex = f.result()

    # Byte order little is how the bitmap is stored in the indexer originally
    bitmap = int.from_bytes(idx.empty_bucket_bitmap, byteorder='little')

    # We are looking to find cases where the bitmap generated by the user query
    # gives a 0, but the bitmap of the repo is a 1.
    # We do not want to count cases where the repo bitmap contains 0 but
    # the user bitmap contains 1, since these are already accounted for by not
    # having these in the query results in the first place.
    # A bitwise NOT on the user query bitmap followed by a bitwise AND satisfies
    # this requirement.
    missed_empty_buckets = (inverted_empty_bucket_bitmap & bitmap).bit_count()

    estimated_num_diff = estimate_diff(
        _BUCKET_SIZE -
        bucket_matches_by_proj[idx.key]  # Buckets that match are not changed
        - empty_bucket_count  # Buckets that are empty are not changed
        + missed_empty_buckets  # Unless they don't match the bitmap
        - num_skipped_buckets,  # Buckets skipped are assumed unchanged
        abs(idx.file_count - max_files)  # The difference in file count
    )

    version_match = osv_service_v1_pb2.VersionMatch(
        score=(max_files - estimated_num_diff) / max_files,
        minimum_file_matches=file_matches_by_proj[idx.key],
        estimated_diff_files=estimated_num_diff,
        repo_info=osv_service_v1_pb2.VersionRepositoryInformation(
            type=osv_service_v1_pb2.VersionRepositoryInformation.GIT,
            address=idx.repo_addr,
            commit=idx.commit,
            version=idx.version,
        ),
    )

    if version_match.score < _DETERMINE_VER_MIN_SCORE_CUTOFF:
      continue

    output.append(version_match)

  return osv_service_v1_pb2.VersionMatchList(matches=output)


def estimate_diff(num_bucket_change: int, file_count_diff: int) -> int:
  """
  Estimates the number of files that have changed based on 
  the number of buckets that changed.
  """
  estimate = _BUCKET_SIZE * math.log(
      (_BUCKET_SIZE + 1) / (_BUCKET_SIZE - num_bucket_change + 1))

  return file_count_diff + round(max(estimate - file_count_diff, 0) / 2)


@ndb.tasklet
def determine_version(version_query: osv_service_v1_pb2.VersionQuery,
                      _: grpc.ServicerContext) -> ndb.Future:
  """Identify fitting commits based on a subset of hashes"""
  req_list = [osv.FileResult(hash=x.hash) for x in version_query.file_hashes]

  # Build all the buckets and query the bucket hash
  buckets = process_buckets(req_list)

  file_match_count: dict[ndb.Key, int] = defaultdict(int)
  bucket_match_count: dict[ndb.Key, int] = defaultdict(int)
  num_skipped_buckets = 0
  skipped_files = 0

  # 1 means not empty, 0 means empty
  empty_bucket_bitmap = 0

  # Tuple is (Future, index, number_of_files)
  query_futures: list[tuple[ndb.Future, int, int]] = []

  for idx, bucket in enumerate(buckets):
    if bucket.files_contained == 0:
      continue

    empty_bucket_bitmap |= 1 << idx
    query = osv.RepoIndexBucket.query(
        osv.RepoIndexBucket.node_hash == bucket.node_hash)
    # Limit the number of requests to prevent super long queries
    query_futures.append((query.fetch_async(limit=_MAX_MATCHES_TO_CARE), idx,
                          bucket.files_contained))

  # Take the results and group the library versions,
  # aggregating on the number of files matched

  for future, idx, num_of_files in query_futures:
    result: list[osv.RepoIndexBucket] = list(future.result())
    if result:  # If there is a match, add it to list of potential versions
      # If it equals the limit, there probably is more versions beyond the limit
      # so just ignore it completely since it's not a useful indicator
      if len(result) == _MAX_MATCHES_TO_CARE:
        num_skipped_buckets += 1
        skipped_files += num_of_files
        continue

      for index_bucket in result:
        parent_key = index_bucket.key.parent()
        file_match_count[parent_key] += index_bucket.files_contained
        bucket_match_count[parent_key] += 1

  # Up the matches by the ones that match too commonly
  # This is used to return 100% matches
  for key in file_match_count.keys():
    file_match_count[key] += skipped_files

  return build_determine_version_result(file_match_count, bucket_match_count,
                                        num_skipped_buckets,
                                        empty_bucket_bitmap,
                                        len(version_query.file_hashes))


@ndb.tasklet
def do_query(query, context: grpc.ServicerContext, include_details=True):
  """Do a query."""
  if query.HasField('package'):
    package_name = query.package.name
    ecosystem = query.package.ecosystem
    purl_str = query.package.purl
  else:
    package_name = ''
    ecosystem = ''
    purl_str = ''

  page_token = None
  if query.page_token:
    page_token = ndb.Cursor(urlsafe=query.page_token)

  purl = None
  purl_version = None
  if purl_str:
    try:
      parsed_purl = PackageURL.from_string(purl_str)
      purl_version = parsed_purl.version
      purl = _clean_purl(parsed_purl)
    except ValueError:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid Package URL.')
      return None

  def to_response(b):
    return bug_to_response(b, include_details)

  next_page_token = None

  if query.WhichOneof('param') == 'commit':
    try:
      commit_bytes = codecs.decode(query.commit, 'hex')
    except ValueError:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid hash.')
      return None

    bugs = yield query_by_commit(commit_bytes, to_response=to_response)
  elif purl and purl_version:
    bugs = yield query_by_version(
        context,
        package_name,
        ecosystem,
        purl,
        purl_version,
        to_response=to_response)
  elif query.WhichOneof('param') == 'version':
    bugs = yield query_by_version(
        context,
        package_name,
        ecosystem,
        purl,
        query.version,
        to_response=to_response)
  elif (package_name != '' and ecosystem != '') or (purl and not purl_version):
    # Package specified without version.
    bugs, next_page_token = yield query_by_package(
        context,
        package_name,
        ecosystem,
        purl,
        page_token,
        to_response=to_response)
  else:
    context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid query.')
    return None

  if next_page_token:
    next_page_token = next_page_token.urlsafe()

  return bugs, next_page_token


def bug_to_response(bug, include_details=True):
  """Convert a Bug entity to a response object."""
  if include_details:
    return bug.to_vulnerability(include_source=True)

  return bug.to_vulnerability_minimal()


def _get_bugs(bug_ids, to_response=bug_to_response):
  """Get bugs from bug ids."""
  bugs = ndb.get_multi([ndb.Key(osv.Bug, bug_id) for bug_id in bug_ids])
  return [
      to_response(bug)
      for bug in bugs
      if bug and bug.status == osv.BugStatus.PROCESSED
  ]


def _clean_purl(purl):
  """
  Clean a purl object.

  Removes version, subpath, and qualifiers with the exception of
  the 'arch' qualifier
  """
  values = purl.to_dict()
  values.pop('version', None)
  values.pop('subpath', None)
  qualifiers = values.pop('qualifiers', None)
  new_qualifiers = {}
  if qualifiers and 'arch' in qualifiers:  # CPU arch for debian packages
    new_qualifiers['arch'] = qualifiers['arch']
  return PackageURL(qualifiers=new_qualifiers, **values)


@ndb.tasklet
def query_by_commit(commit, to_response=bug_to_response):
  """Query by commit."""
  query = osv.AffectedCommits.query(osv.AffectedCommits.commits == commit)
  bug_ids = []
  it = query.iter()
  while (yield it.has_next_async()):
    affected_commits = it.next()
    # Avoid requiring a separate index to include this in the initial Datastore
    # query. The number of these should be very little to just iterate through.
    if not affected_commits.public:
      continue
    bug_ids.append(affected_commits.bug_id)

  return _get_bugs(bug_ids, to_response=to_response)


def _match_purl(purl_query: PackageURL, purl_db: PackageURL) -> bool:
  """Check if purl match at the specifity level of purl_query

  If purl_query doesn't have qualifiers, then we will match against purl_db
  without qualifiers, otherwise match with qualifiers
  """

  if not purl_query.qualifiers:
    # No qualifiers, and our PURLs never have versions, so just match name
    return purl_query.name == purl_db.name

  return purl_query == purl_db


def _is_semver_affected(affected_packages, package_name, ecosystem,
                        purl: PackageURL, version):
  """Returns whether or not the given version is within an affected SEMVER

  range.
  """
  version = semver_index.parse(version)

  affected = False
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem and ecosystem != affected_package.package.ecosystem:
      continue

    if purl and not (affected_package.package.purl and _match_purl(
        purl, PackageURL.from_string(affected_package.package.purl))):
      continue

    for affected_range in affected_package.ranges:
      if affected_range.type != 'SEMVER':
        continue

      for event in osv.sorted_events('', affected_range.type,
                                     affected_range.events):
        if (event.type == 'introduced' and
            (event.value == '0' or version >= semver_index.parse(event.value))):
          affected = True

        if event.type == 'fixed' and version >= semver_index.parse(event.value):
          affected = False

        if event.type == 'last_affected' and version > semver_index.parse(
            event.value):
          affected = False

      if affected:
        return affected

  return affected


def _is_version_affected(affected_packages,
                         package_name,
                         ecosystem,
                         purl: PackageURL,
                         version,
                         normalize=False):
  """Returns whether or not the given version is within an affected ECOSYSTEM

  range.
  """
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem:
      # If package ecosystem has a :, also try ignoring parts after it.
      if (affected_package.package.ecosystem != ecosystem and
          ecosystems.normalize(
              affected_package.package.ecosystem) != ecosystem):
        continue

    if purl and not (affected_package.package.purl and _match_purl(
        purl, PackageURL.from_string(affected_package.package.purl))):
      continue

    if normalize:
      if any(
          osv.normalize_tag(version) == osv.normalize_tag(v)
          for v in affected_package.versions):
        return True
    else:
      if version in affected_package.versions:
        return True

  return False


@ndb.tasklet
def _query_by_semver(context: grpc.ServicerContext, query: ndb.Query,
                     package_name: str, ecosystem: str, purl: PackageURL,
                     version: str):
  """Query by semver."""
  if not semver_index.is_valid(version):
    return []

  results = []
  query = query.filter(
      osv.Bug.semver_fixed_indexes > semver_index.normalize(version))
  it = query.iter(
      timeout=min(_MAX_REQUEST_DURATION_SECS, context.time_remaining()))

  while (yield it.has_next_async()):
    bug = it.next()
    if _is_semver_affected(bug.affected_packages, package_name, ecosystem, purl,
                           version):
      results.append(bug)

  return results


@ndb.tasklet
def _query_by_generic_version(context: grpc.ServicerContext,
                              base_query: ndb.Query, project, ecosystem,
                              purl: PackageURL, version):
  """Query by generic version."""
  # Try without normalizing.
  results = []
  query = base_query.filter(osv.Bug.affected_fuzzy == version)
  it = query.iter()
  while (yield it.has_next_async()):
    bug = it.next()
    if _is_version_affected(bug.affected_packages, project, ecosystem, purl,
                            version):
      results.append(bug)

  if results:
    return results

  # Try again after normalizing.
  version = osv.normalize_tag(version)
  query = base_query.filter(osv.Bug.affected_fuzzy == version)
  it = query.iter(
      timeout=min(_MAX_REQUEST_DURATION_SECS, context.time_remaining()))
  while (yield it.has_next_async()):
    bug = it.next()
    if _is_version_affected(
        bug.affected_packages,
        project,
        ecosystem,
        purl,
        version,
        normalize=True):
      results.append(bug)

  return results


@ndb.tasklet
def query_by_version(context: grpc.ServicerContext,
                     package_name: str,
                     ecosystem: str,
                     purl: PackageURL,
                     version,
                     to_response=bug_to_response):
  """Query by (fuzzy) version."""
  ecosystem_info = ecosystems.get(ecosystem)
  is_semver = ecosystem_info and ecosystem_info.is_semver

  if package_name == "Kernel":
    context.abort(
        grpc.StatusCode.UNAVAILABLE,
        "Linux Kernel queries are currently unavailable: " +
        "See https://google.github.io/osv.dev/faq/" +
        "#why-am-i-getting-an-error-message-for-my-linux-kernel-query")

  if package_name:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.project == package_name,
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  elif purl:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.purl == purl.to_string(),
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  else:
    return []

  if ecosystem:
    query = query.filter(osv.Bug.ecosystem == ecosystem)

  bugs = []
  if ecosystem:
    if is_semver:
      # Ecosystem supports semver only.
      bugs.extend((yield _query_by_semver(context, query, package_name,
                                          ecosystem, purl, version)))
    else:
      bugs.extend((yield _query_by_generic_version(context, query, package_name,
                                                   ecosystem, purl, version)))
  else:
    # Unspecified ecosystem. Try both.
    bugs.extend((yield _query_by_semver(context, query, package_name, ecosystem,
                                        purl, version)))
    bugs.extend((yield _query_by_generic_version(context, query, package_name,
                                                 ecosystem, purl, version)))

  return [to_response(bug) for bug in bugs]


@ndb.tasklet
def query_by_package(context: grpc.ServicerContext, package_name: str,
                     ecosystem: str, purl: PackageURL, page_token, to_response):
  """Query by package."""
  bugs = []
  if package_name and ecosystem:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.project == package_name,
        osv.Bug.ecosystem == ecosystem,
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  elif purl:
    query = osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.purl == purl.to_string(),
        # pylint: disable=singleton-comparison
        osv.Bug.public == True,  # noqa: E712
    )
  else:
    return []

  # Set limit to the max + 1, as otherwise we can't detect if there are any
  # more left.
  it = query.iter(
      start_cursor=page_token,
      limit=_MAX_VULNERABILITIES_LISTED + 1,
      timeout=min(_MAX_REQUEST_DURATION_SECS, context.time_remaining()))
  cursor = None
  while (yield it.has_next_async()):
    if len(bugs) >= _MAX_VULNERABILITIES_LISTED:
      cursor = it.cursor_after()
      break

    bugs.append(it.next())

  return [to_response(bug) for bug in bugs], cursor


def serve(port: int, local: bool):
  """Configures and runs the OSV API server."""
  server = grpc.server(concurrent.futures.ThreadPoolExecutor(max_workers=10))
  osv_service_v1_pb2_grpc.add_OSVServicer_to_server(OSVServicer(), server)
  if local:
    service_names = (
        osv_service_v1_pb2.DESCRIPTOR.services_by_name['OSV'].full_name,
        reflection.SERVICE_NAME,
    )
    reflection.enable_server_reflection(service_names, server)
  server.add_insecure_port('[::]:{}'.format(port))
  server.start()

  print('Listening on port {}'.format(port))
  try:
    while True:
      time.sleep(3600)
  except KeyboardInterrupt:
    print('Shutting down with {} grace period'.format(_SHUTDOWN_GRACE_DURATION))
    server.stop(_SHUTDOWN_GRACE_DURATION)


def is_cloud_run() -> bool:
  """Check if we are running in Cloud Run."""
  # https://cloud.google.com/run/docs/container-contract#env-vars
  return os.getenv('K_SERVICE') is not None


def main():
  """Entrypoint."""
  if is_cloud_run():
    setup_gcp_logging('api-backend')

  logging.getLogger().setLevel(logging.INFO)

  parser = argparse.ArgumentParser(
      formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument(
      '--port',
      type=int,
      default=None,
      help='The port to listen on.'
      'If arg is not set, will listen on the $PORT env var.'
      'If env var is empty, defaults to 8000.')
  parser.add_argument(
      '--local',
      action='store_true',
      default=False,
      help='If set reflection is enabled to allow debugging with grpcurl.')

  args = parser.parse_args()
  port = args.port
  if not port:
    port = os.environ.get('PORT')
  if not port:
    port = 8000

  serve(port, args.local)


if __name__ == '__main__':
  main()
