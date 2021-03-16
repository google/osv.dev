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

import osv
import osv_service_v1_pb2
import osv_service_v1_pb2_grpc

_PROJECT = 'oss-vdb'
_OSS_FUZZ_TRACKER_URL = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='

_SHUTDOWN_GRACE_DURATION = 5

_AUTHORIZATION_HEADER_PREFIX = 'Bearer '
_EXPECTED_AUDIENCE = 'https://db.oss-fuzz.com'

_ndb_client = ndb.Client()


def ndb_context(func):
  """Wrapper to create an NDB context."""

  @functools.wraps(func)
  def wrapper(*args, **kwargs):
    with _ndb_client.context():
      return func(*args, **kwargs)

  return wrapper


class BaseServicer:
  """Base servicer."""

  def is_privileged(self, context):
    """Check whether if the calling client is privileged."""
    for key, _ in context.invocation_metadata():
      # If we have this metadata value, it means it passed JWT validation.
      if key == 'x-endpoint-api-userinfo':
        return True

    return False


class OSVServicer(osv_service_v1_pb2_grpc.OSVServicer, BaseServicer):
  """V1 OSV servicer."""

  @ndb_context
  def GetVulnById(self, request, context):
    """Return a `Vulnerability` object for a given OSV ID.
    """
    bug = osv.Bug.get_by_id(request.id)
    if not bug or bug.status == osv.BugStatus.UNPROCESSED:
      context.abort(grpc.StatusCode.NOT_FOUND, 'Bug not found.')
      return None

    if not bug.public and not self.is_privileged(context):
      context.abort(grpc.StatusCode.PERMISSION_DENIED, 'Permission denied.')
      return None

    return bug_to_response(bug)

  @ndb_context
  def QueryAffected(self, request, context):
    """Query vulnerabilities for a particular project at a given commit or
    version."""
    privileged = self.is_privileged(context)
    if request.query.HasField('package'):
      package_name = request.query.package.name
      ecosystem = request.query.package.ecosystem
    else:
      package_name = ''
      ecosystem = ''

    if request.query.WhichOneof('param') == 'commit':
      bugs = query_by_commit(
          package_name,
          ecosystem,
          request.query.commit,
          privileged,
          to_response=bug_to_response)
    elif request.query.WhichOneof('param') == 'version':
      bugs = query_by_version(
          package_name,
          ecosystem,
          request.query.version,
          privileged,
          to_response=bug_to_response)
    else:
      context.abort(grpc.StatusCode.INVALID_ARGUMENT, 'Invalid query.')

    return osv_service_v1_pb2.VulnerabilityList(vulns=bugs)

  def GetVulnByIdNew(self, request, context):
    """Return a `Vulnerability` object for a given OSV ID.
    """
    return self.GetVulnById(request, context)

  def QueryAffectedNew(self, request, context):
    """Query vulnerabilities for a particular project at a given commit or
    version."""
    return self.QueryAffected(request, context)


def bug_to_response(bug):
  """Convert a Bug entity to a response object."""
  return bug.to_vulnerability()


def _get_bugs(bug_ids, to_response=bug_to_response):
  """Get bugs from bug ids."""
  bugs = ndb.get_multi([ndb.Key(osv.Bug, bug_id) for bug_id in bug_ids])
  return [
      to_response(bug)
      for bug in bugs
      if bug and bug.status == osv.BugStatus.PROCESSED
  ]


def query_by_commit(project,
                    ecosystem,
                    commit,
                    privileged,
                    to_response=bug_to_response):
  """Query by commit."""
  query = osv.AffectedCommit.query(osv.AffectedCommit.commit == commit)

  if project:
    query = query.filter(osv.AffectedCommit.project == project)

  if ecosystem:
    query = query.filter(osv.AffectedCommit.ecosystem == ecosystem)

  if not privileged:
    query = query.filter(osv.AffectedCommit.public == True)  # pylint: disable=singleton-comparison

  bug_ids = []
  for affected_commit in query:
    bug_ids.append(affected_commit.bug_id)

  return _get_bugs(bug_ids, to_response=to_response)


def query_by_tag(project,
                 ecosystem,
                 tag,
                 privileged,
                 to_response=bug_to_response):
  """Query by tag."""
  query = osv.Bug.query(osv.Bug.project == project,
                        osv.Bug.ecosystem == ecosystem, osv.Bug.affected == tag)

  if not privileged:
    query = query.filter(osv.Bug.public == True)  # pylint: disable=singleton-comparison

  bugs = []
  for bug in query:
    bugs.append(bug)

  return [to_response(bug) for bug in bugs]


def query_by_version(project,
                     ecosystem,
                     version,
                     privileged,
                     to_response=bug_to_response):
  """Query by (fuzzy) version."""

  query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                        osv.Bug.project == project,
                        osv.Bug.affected_fuzzy == osv.normalize_tag(version))

  if ecosystem:
    query = query.filter(osv.Bug.ecosystem == ecosystem)

  if not privileged:
    query = query.filter(osv.Bug.public == True)  # pylint: disable=singleton-comparison

  bugs = []
  for bug in query:
    bugs.append(bug)

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
