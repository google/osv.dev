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
from concurrent import futures
import functools
import logging
import os
import sys
import time

from google.cloud import ndb
import grpc
from packageurl import PackageURL

import osv
from osv import ecosystems
from osv import semver_index
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

_PROJECT = 'oss-vdb'
_OSS_FUZZ_TRACKER_URL = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='

_SHUTDOWN_GRACE_DURATION = 5

_AUTHORIZATION_HEADER_PREFIX = 'Bearer '
_EXPECTED_AUDIENCE = 'https://db.oss-fuzz.com'

_MAX_BATCH_QUERY = 1000

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
    """Return a `Vulnerability` object for a given OSV ID.
    """
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
    version."""
    results = do_query(request.query, context).result()
    if results is not None:
      return osv_service_v1_pb2.VulnerabilityList(vulns=results)

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
          osv_service_v1_pb2.VulnerabilityList(vulns=future.result() or []))

    return osv_service_v1_pb2.BatchVulnerabilityList(results=batch_results)


@ndb.tasklet
def do_query(query, context, include_details=True):
  """Do a query."""
  if query.HasField('package'):
    package_name = query.package.name
    ecosystem = query.package.ecosystem
    purl = query.package.purl
  else:
    package_name = ''
    ecosystem = ''
    purl = ''

  purl_version = None
  if purl:
    try:
      parsed_purl = PackageURL.from_string(purl)
      purl_version = parsed_purl.version
      purl = _clean_purl(parsed_purl).to_string()
    except ValueError:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid Package URL.')
      return None

  to_response = lambda b: bug_to_response(b, include_details)

  if query.WhichOneof('param') == 'commit':
    bugs = yield query_by_commit(query.commit, to_response=to_response)
  elif purl and purl_version:
    bugs = yield query_by_version(
        package_name, ecosystem, purl, purl_version, to_response=to_response)
  elif query.WhichOneof('param') == 'version':
    bugs = yield query_by_version(
        package_name, ecosystem, purl, query.version, to_response=to_response)
  else:
    context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid query.')
    return None

  return bugs


def bug_to_response(bug, include_details=True):
  """Convert a Bug entity to a response object."""
  if include_details:
    return bug.to_vulnerability(include_source=True)

  return {'id': bug.id()}


def _get_bugs(bug_ids, to_response=bug_to_response):
  """Get bugs from bug ids."""
  bugs = ndb.get_multi([ndb.Key(osv.Bug, bug_id) for bug_id in bug_ids])
  return [
      to_response(bug)
      for bug in bugs
      if bug and bug.status == osv.BugStatus.PROCESSED
  ]


def _clean_purl(purl):
  """Clean a purl object."""
  values = purl.to_dict()
  values.pop('version', None)
  values.pop('subpath', None)
  values.pop('qualifiers', None)
  return PackageURL(**values)


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


def _is_semver_affected(affected_packages, package_name, ecosystem, purl,
                        version):
  """Returns whether or not the given version is within an affected SEMVER
  range."""
  version = semver_index.parse(version)

  affected = False
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem and ecosystem != affected_package.package.ecosystem:
      continue

    if purl and purl != affected_package.package.purl:
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

  return affected


def _is_version_affected(affected_packages,
                         package_name,
                         ecosystem,
                         purl,
                         version,
                         normalize=False):
  """Returns whether or not the given version is within an affected ECOSYSTEM
  range."""
  for affected_package in affected_packages:
    if package_name and package_name != affected_package.package.name:
      continue

    if ecosystem and ecosystem != affected_package.package.ecosystem:
      continue

    if purl and purl != affected_package.package.purl:
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
def _query_by_semver(query, package_name, ecosystem, purl, version):
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
def _query_by_generic_version(base_query, project, ecosystem, purl, version):
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
def query_by_version(project,
                     ecosystem,
                     purl,
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
                          osv.Bug.purl == purl, osv.Bug.public == True)  # pylint: disable=singleton-comparison
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


def serve(port):
  """Configures and runs the bookstore API server."""
  server = grpc.server(futures.ThreadPoolExecutor(max_workers=10))
  osv_service_v1_pb2_grpc.add_OSVServicer_to_server(OSVServicer(), server)
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

  args = parser.parse_args()
  port = args.port
  if not port:
    port = os.environ.get('PORT')
  if not port:
    port = 8000

  serve(port)


if __name__ == '__main__':
  main()
