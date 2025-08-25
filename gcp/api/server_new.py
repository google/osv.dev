# Copyright 2025 Google LLC
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
"""OSV API Server logic reimplemented using the new AffectedVersions entities"""

import concurrent.futures
import logging
from packaging.utils import canonicalize_version

from google.cloud import exceptions
from google.cloud import ndb
from google.cloud.ndb import tasklets
from google.protobuf import timestamp_pb2

import osv

from cursor import QueryCursorMetadata

# TODO(michaelkedar): A Global ThreadPoolExecutor is not ideal.
_BUCKET_THREAD_POOL = concurrent.futures.ThreadPoolExecutor(max_workers=32)


@ndb.tasklet
def query_package(context,
                  package_name: str | None,
                  ecosystem: str | None,
                  version: str | None,
                  include_details: bool = True) -> list[ndb.Future]:
  """
  Queries for vulnerabilities by package and version using a new data model.

  This function is designed to test a new query path that may use different
  data sources (like GCS) for fetching vulnerability details.

  Args:
    context: The QueryContext for the current request.
    package_name: The name of the package.
    ecosystem: The package's ecosystem.
    version: The version of the package to query for.
    include_details: Whether to return full or minimal vulnerability details.

  Returns:
    A list of Vulnerability protos.
  """

  context.query_counter += 1
  if context.should_skip_query():
    return []

  # Bare minimum we need a package name.
  if not package_name:
    return []

  query = osv.AffectedVersions.query(osv.AffectedVersions.name == package_name)
  if ecosystem:
    query = query.filter(osv.AffectedVersions.ecosystem == ecosystem)
  query = query.order(osv.AffectedVersions.vuln_id)

  bugs = []
  last_matched_id = ''
  if query_cursor := context.input_cursor:
    if query_cursor.metadata.last_id:
      last_matched_id = query_cursor.metadata.last_id

  it: ndb.QueryIterator = query.iter(start_cursor=context.cursor_at_current())
  while (yield it.has_next_async()):
    if context.should_break_page(len(bugs)):
      meta = QueryCursorMetadata(
          last_id=last_matched_id) if last_matched_id else None
      context.save_cursor_at_page_break(it, meta)
      break

    affected: osv.AffectedVersions = it.next()
    if affected.vuln_id == last_matched_id:
      continue
    if not version or affected_affects(version, affected):
      if include_details:
        bugs.append(get_vuln_async(affected.vuln_id))
      else:
        bugs.append(get_minimal_async(affected.vuln_id))
      last_matched_id = affected.vuln_id
      context.total_responses.add(1)

  return bugs


def affected_affects(version: str, affected: osv.AffectedVersions) -> bool:
  """Check if a given version is affected by the AffectedVersions entry."""
  if len(affected.versions) > 0:
    return _match_versions(version, affected)
  if len(affected.events) > 0:
    return _match_events(version, affected)

  logging.warning('AffectedVersion %s (%s) has no events or versions',
                  affected.key, affected.vuln_id)
  return False


def _match_versions(version: str, affected: osv.AffectedVersions) -> bool:
  """Check if the given version matches one of the AffectedVersions' listed 
  versions."""
  ecosystem_helper = osv.ecosystems.get(affected.ecosystem)
  if ecosystem_helper and (ecosystem_helper.supports_comparing or
                           ecosystem_helper.is_semver):
    # Most ecosystem helpers return a very large version on invalid, but if it
    # does cause an error, just match nothing.
    try:
      parsed_version = ecosystem_helper.sort_key(version)
    except:
      # TODO(michaelkedar): This log is noisy.
      logging.error('Ecosystem helper for %s raised an exception',
                    affected.ecosystem)
      return False

    for v in affected.versions:
      try:
        if ecosystem_helper.sort_key(v) == parsed_version:
          return True
      except:
        logging.error('Version %s in AffectedVersion %s (%s) does not parse', v,
                      affected.key, affected.vuln_id)
    return False

  # Helper not implemented:
  # Direct string matching
  if version in affected.versions:
    return True
  # Try fuzzy matching
  vers = affected.versions
  if affected.ecosystem == 'GIT':
    vers = osv.models.maybe_strip_repo_prefixes(vers, [affected.name])
  if osv.normalize_tag(version) in osv.normalize_tags(vers):
    return True
  if canonicalize_version(version) in (
      canonicalize_version(v) for v in affected.versions):
    return True
  return False


def _match_events(version: str, affected: osv.AffectedVersions) -> bool:
  """Check if the given version matches in the AffectedVersions' events list."""
  ecosystem_helper = osv.ecosystems.get(affected.ecosystem)
  if not (ecosystem_helper and
          (ecosystem_helper.supports_comparing or ecosystem_helper.is_semver)):
    # Ecosystem does not support comparisons.
    return False
  try:
    parsed_version = ecosystem_helper.sort_key(version)
  except:
    # TODO(michaelkedar): This log is noisy.
    logging.error('Ecosystem helper for %s raised an exception',
                  affected.ecosystem)
    return False

  # Find where this version would belong in the sorted events list.
  for event in reversed(affected.events):
    try:
      event_ver = ecosystem_helper.sort_key(event.value)
    except:
      # Shouldn't really happen. We use sort_key to sort these before creating
      # the AffectedVersions entity.
      logging.error('Event %s in AffectedVersion %s (%s) does not parse',
                    event.value, affected.key, affected.vuln_id)
      return False
    if event_ver == parsed_version:
      return event.type in ('introduced', 'last_affected')
    if event_ver < parsed_version:
      return event.type == 'introduced'

  return False


@ndb.tasklet
def get_minimal_async(vuln_id: str):
  """Asynchronously get a minimal vulnerability record."""
  vuln = yield osv.Vulnerability.get_by_id_async(vuln_id)
  modified = timestamp_pb2.Timestamp()
  modified.FromDatetime(vuln.modified)
  return osv.vulnerability_pb2.Vulnerability(id=vuln_id, modified=modified)


def get_vuln_async(vuln_id: str) -> ndb.Future:
  """Asynchronously get a full vulnerability record."""

  # As a work around for using external processes with ndb's async,
  # do the bucket get in another thread, and poll it with abd ndb Future.
  f = _BUCKET_THREAD_POOL.submit(osv.gcs.get_by_id, vuln_id)

  @ndb.tasklet
  def async_poll_result():
    while not f.done():
      yield tasklets.sleep(0.1)
    try:
      return f.result()
    except exceptions.NotFound:
      logging.error('Vulnerability %s matched query but not found in GCS',
                    vuln_id)
      osv.pubsub.publish_failure(b'', type='gcs_missing', id=vuln_id)
      return None

  def cleanup(_: ndb.Future):
    f.cancel()

  future = async_poll_result()
  future.add_done_callback(cleanup)
  return future
