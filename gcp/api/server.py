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
import concurrent
import functools
import logging
import os
import sys
import time

from google.cloud import ndb
import grpc
from grpc_reflection.v1alpha import reflection
from packageurl import PackageURL

import osv
from osv import ecosystems
from osv import semver_index
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

from typing import List

_PROJECT = 'oss-vdb'
_OSS_FUZZ_TRACKER_URL = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='

_SHUTDOWN_GRACE_DURATION = 5

_AUTHORIZATION_HEADER_PREFIX = 'Bearer '
_EXPECTED_AUDIENCE = 'https://db.oss-fuzz.com'

_MAX_BATCH_QUERY = 1000
_MAX_VULNERABILITIES_LISTED = 16

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
    if not request.query.name:
      context.abort(grpc.StatusCode.NOT_IMPLEMENTED,
                    'Querying only by file hash is not implemented yet.')
      return None
    return get_version_by_name(request.query).result()


@ndb.tasklet
def get_version_by_name(
    version_query: osv_service_v1_pb2.VersionQuery) -> ndb.Future:
  """Identifies the version based on the provided name."""
  query = osv.RepoIndex.query(osv.RepoIndex.name == version_query.name)
  it = query.iter()
  futures = []
  while (yield it.has_next_async()):
    idx = it.next()
    match = compare_hashes_from_commit(idx, version_query.file_hashes)
    futures.append(match)
  results = []
  for f in futures:
    match = f.result()
    if match.score != 0.0:
      results.append(match)
  return osv_service_v1_pb2.VersionMatchList(matches=results)


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
  return osv_service_v1_pb2.VersionMatch(
      type=osv_service_v1_pb2.VersionMatch.VERSION,
      value=idx.version,
      score=score)


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
    bugs = yield query_by_commit(query.commit, to_response=to_response)
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
  query = osv.AffectedCommit.query(osv.AffectedCommit.commit == commit,
                                   osv.AffectedCommit.public == True)  # pylint: disable=singleton-comparison
  bug_ids = []
  it = query.iter()
  while (yield it.has_next_async()):
    affected_commit = it.next()
    bug_ids.append(affected_commit.bug_id)

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
