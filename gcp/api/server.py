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
"""API server implementation."""

import argparse
import codecs
import concurrent
import cProfile
import timeit
import functools
import logging
import os
import random
import sys
import time
from collections import defaultdict

from google.cloud import ndb
import grpc
from grpc_reflection.v1alpha import reflection
from packageurl import PackageURL

import osv
from osv import ecosystems
from osv import semver_index
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

from typing import Iterable, List

_SHUTDOWN_GRACE_DURATION = 5

_MAX_BATCH_QUERY = 1000
_MAX_VULNERABILITIES_LISTED = 16
_MAX_HASHES_TO_TRY = 50
_MAX_MATCHES_TO_CARE = 1100
_MAX_COMMITS_TO_TRY = 10

_ndb_client = ndb.Client()
profiler = cProfile.Profile()


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
  def GetVulnById(self, request, context):
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
  def QueryAffected(self, request, context):
    """Query vulnerabilities for a particular project at a given commit or

    version.
    """
    results, next_page_token = do_query(request.query, context).result()
    if results is not None:
      return osv_service_v1_pb2.VulnerabilityList(
          vulns=results, next_page_token=next_page_token)

    return None

  @ndb_context
  def QueryAffectedBatch(self, request, context):
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
  def DetermineVersion(self, request, context):
    """Determine the version of the provided hashes."""
    profiler.enable()
    res = determine_version(request.query, context).result()
    profiler.disable()
    profiler.dump_stats("./someoutput.data")
    # profiler.print_stats()
    return res


class Timer:

  def __init__(self):
    self.start_time = timeit.default_timer()
    self.lap_time = timeit.default_timer()

  def elapsed(self):
    current_time = timeit.default_timer()
    logging.info(
        f"Elapsed: {current_time - self.lap_time}  -  From Start: {current_time - self.start_time}"
    )
    self.lap_time = current_time


# Following code straight from chatgpt converted from GO code, look over carefully
from typing import List, Tuple
import math
import hashlib
import functools

chunk_size = 4
bucket_count = 256


def process_tree(
    file_results: List[osv.FileResult]) -> List[osv.RepoIndexResultTree]:
  # height_of_tree = log_with_base(((chunk_size - 1) * bucket_count) + 1,
  #                                chunk_size)
  # results: list[osv.RepoIndexResultTree]
  buckets: list[list[bytes]] = [[] for _ in range(bucket_count)]

  for fr in file_results:
    buckets[fr.hash[0]].append(fr.hash)

  results: list[osv.RepoIndexResultTree] = [None] * bucket_count
  for bucket_idx, bucket in enumerate(buckets):
    buckets[bucket_idx].sort()

    hasher = hashlib.md5()
    for v in buckets[bucket_idx]:
      hasher.update(v)

    results[bucket_idx] = osv.RepoIndexResultTree(
        node_hash=hasher.digest(),
        child_hashes=buckets[bucket_idx],
        depth=0,
        files_contained=len(buckets[bucket_idx]),
    )

  # for height in range(1, len(results)):
  #   results[height] = [None] * (len(results[height - 1]) // chunk_size)
  #   for i in range(0, len(results[height - 1]), chunk_size):
  #     hasher = hashlib.md5()
  #     child_hashes = []
  #     files_contained = 0

  #     for v in results[height - 1][i:i + chunk_size]:
  #       hasher.update(v.node_hash)
  #       child_hashes.append(v.node_hash)
  #       files_contained += v.files_contained

  #     parent_idx = i // chunk_size
  #     results[height][parent_idx] = osv.RepoIndexResultTree(
  #         node_hash=hasher.digest(),
  #         child_hashes=child_hashes,
  #         depth=height,
  #         files_contained=files_contained,
  #     )

  return results


def log_with_base(x: int, base: int) -> int:
  return math.ceil(math.log(x) / math.log(base))


# Above code straight from chatgpt converted from GO code, look over carefully


def build_determine_version_result(
    candidate_files: dict[ndb.Key, int], candidate_buckets: dict[ndb.Key, int],
    max_files: int) -> osv_service_v1_pb2.VersionMatchList:
  idx_futures = ndb.get_multi_async(candidate_files.keys())
  output = []
  for f in idx_futures:
    idx: osv.RepoIndex = f.result()
    logging.info(bucket_count - candidate_buckets[idx.key])
    version_match = osv_service_v1_pb2.VersionMatch(
        score=candidate_files[idx.key] / max_files,
        minimum_file_matches=candidate_files[idx.key],
        estimated_diff_files=estimate_diff(bucket_count -
                                           candidate_buckets[idx.key]),
        repo_info=osv_service_v1_pb2.VersionRepositoryInformation(
            type=osv_service_v1_pb2.VersionRepositoryInformation.GIT,
            address=idx.repo_addr,
            commit=idx.commit,
            version=idx.version,
        ),
    )
    output.append(version_match)

  output.sort(reverse=True, key=lambda x: x.score)
  return osv_service_v1_pb2.VersionMatchList(
      matches=output[:min(5, len(output))])


def estimate_diff(num_of_bucket_change: int) -> int:
  estimate = bucket_count * math.log(
      (bucket_count + 1) / (bucket_count - num_of_bucket_change + 1))
  return round(estimate / 2)


@ndb.tasklet
def determine_version(version_query: osv_service_v1_pb2.VersionQuery,
                      context: grpc.ServicerContext) -> ndb.Future:
  """Identify fitting commits based on a subset of hashes"""

  timer = Timer()
  logging.info(len(version_query.file_hashes))

  req_list = [osv.FileResult(hash=x.hash) for x in version_query.file_hashes]
  # req_set = {x.hash for x in version_query.file_hashes}

  layer = process_tree(req_list)

  candidates_files: dict[ndb.Key, int] = defaultdict(int)
  candidates_buckets: dict[ndb.Key, int] = defaultdict(int)
  logging.info('Begin query tree')
  timer.elapsed()

  query_futures: list[tuple[ndb.Future, int]] = []
  # not_match_count = 0
  for idx, node in enumerate(layer):
    if node.files_contained == 0:
      continue

    query = osv.RepoIndexResultTree.query(
        osv.RepoIndexResultTree.node_hash == node.node_hash)
    query_futures.append((query.fetch_async(limit=_MAX_MATCHES_TO_CARE), idx))

  logging.info(len(query_futures))
  for future, idx in query_futures:
    result: list[osv.RepoIndexResultTree] = list(future.result())
    if result:  # If there is a match, add it to list of potential versions
      if len(result) == _MAX_MATCHES_TO_CARE:
        logging.info("AHHHHHHHHHHHH")
        continue

      for hash in result:
        parent_key = hash.key.parent()
        candidates_files[parent_key] += hash.files_contained
        candidates_buckets[parent_key] += 1

  logging.info('Tree match complete:')
  # logging.info(f'{len(not_matched_buckets)} of 256 buckets does not match')
  # logging.info(f'{estimate_diff(len(not_matched_buckets))} estimated files changed')
  # logging.info(f'{not_match_count} files potentially need to be scanned')
  # logging.info(f'{len(candidates_files)} potential versions match')
  # timer.elapsed()

  timer.elapsed()
  return build_determine_version_result(candidates_files, candidates_buckets,
                                        len(version_query.file_hashes))


@ndb.tasklet
def compare_hashes_from_commit(
    idx: osv.RepoIndex,
    hashes: List[osv_service_v1_pb2.FileHash]) -> ndb.Future:
  """"Retrieves the hashes from the provided index and compares
      them to the input hashes."""
  total_files = 0
  matching_hashes = 0
  for i in range(idx.pages):
    key = version_hashes_key(idx.key, idx.commit, idx.file_hash_type, i)
    result = key.get()
    for f_result in result.file_results:
      for in_hash in hashes:
        if in_hash.hash == f_result.hash:
          matching_hashes += 1
          break
      total_files += 1
  score = matching_hashes / total_files if total_files != 0 else 0.0
  version_match = osv_service_v1_pb2.VersionMatch(
      score=score,
      repo_info=osv_service_v1_pb2.VersionRepositoryInformation(
          type=osv_service_v1_pb2.VersionRepositoryInformation.GIT,
          address=idx.repo_addr,
          commit=idx.commit,
          version=idx.version,
      ),
  )
  return version_match


def version_hashes_key(parent_key: ndb.Key, commit: bytes, hash_type: str,
                       page: int) -> ndb.Key:
  return ndb.Key(parent_key.kind(), parent_key.id(), osv.RepoIndexResult,
                 f"{commit.hex()}-{hash_type}-{page}")


@ndb.tasklet
def do_query(query, context, include_details=True):
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
        package_name, ecosystem, purl, purl_version, to_response=to_response)
  elif query.WhichOneof('param') == 'version':
    bugs = yield query_by_version(
        package_name, ecosystem, purl, query.version, to_response=to_response)
  elif (package_name != '' and ecosystem != '') or (purl and not purl_version):
    # Package specified without version.
    bugs, next_page_token = yield query_by_package(
        package_name, ecosystem, purl, page_token, to_response=to_response)
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
def _query_by_semver(query, package_name, ecosystem, purl: PackageURL, version):
  """Query by semver."""
  if not semver_index.is_valid(version):
    return []

  results = []
  query = query.filter(
      osv.Bug.semver_fixed_indexes > semver_index.normalize(version))
  it = query.iter()

  while (yield it.has_next_async()):
    bug = it.next()
    if _is_semver_affected(bug.affected_packages, package_name, ecosystem, purl,
                           version):
      results.append(bug)

  return results


@ndb.tasklet
def _query_by_generic_version(base_query, project, ecosystem, purl: PackageURL,
                              version):
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
  it = query.iter()
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
def query_by_version(project: str,
                     ecosystem: str,
                     purl: PackageURL,
                     version,
                     to_response=bug_to_response):
  """Query by (fuzzy) version."""
  ecosystem_info = ecosystems.get(ecosystem)
  is_semver = ecosystem_info and ecosystem_info.is_semver
  if project:
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.project == project, osv.Bug.public == True)  # pylint: disable=singleton-comparison
  elif purl:
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.purl == purl.to_string(),
                          osv.Bug.public == True)  # pylint: disable=singleton-comparison
  else:
    return []

  if ecosystem:
    query = query.filter(osv.Bug.ecosystem == ecosystem)

  bugs = []
  if ecosystem:
    if is_semver:
      # Ecosystem supports semver only.
      bugs.extend((yield _query_by_semver(query, project, ecosystem, purl,
                                          version)))
    else:
      bugs.extend((yield _query_by_generic_version(query, project, ecosystem,
                                                   purl, version)))
  else:
    # Unspecified ecosystem. Try both.
    bugs.extend((yield _query_by_semver(query, project, ecosystem, purl,
                                        version)))
    bugs.extend((yield _query_by_generic_version(query, project, ecosystem,
                                                 purl, version)))

  return [to_response(bug) for bug in bugs]


@ndb.tasklet
def query_by_package(project, ecosystem, purl: PackageURL, page_token,
                     to_response):
  """Query by package."""
  bugs = []
  if project and ecosystem:
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.project == project,
                          osv.Bug.ecosystem == ecosystem,
                          osv.Bug.public == True)  # pylint: disable=singleton-comparison
  elif purl:
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.purl == purl.to_string(),
                          osv.Bug.public == True)  # pylint: disable=singleton-comparison
  else:
    return []

  # Set limit to the max + 1, as otherwise we can't detect if there are any
  # more left.
  it = query.iter(
      start_cursor=page_token, limit=_MAX_VULNERABILITIES_LISTED + 1)
  cursor = None
  while (yield it.has_next_async()):
    if len(bugs) >= _MAX_VULNERABILITIES_LISTED:
      cursor = it.cursor_after()
      break

    bugs.append(it.next())

  return [to_response(bug) for bug in bugs], cursor


def serve(port: int, local: bool):
  """Configures and runs the bookstore API server."""
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
    server.stop(_SHUTDOWN_GRACE_DURATION)


def main():
  """Entrypoint."""
  logging.basicConfig(stream=sys.stderr)
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
