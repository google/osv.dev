#!/usr/bin/env python3
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
"""OSV Upstream relation computation."""

from collections import defaultdict
import datetime
import json
import logging
import os

from google.cloud import ndb
from google.protobuf import json_format

import osv
import osv.logs
from osv import gcs


def compute_upstream(target_bug, bugs: dict[str, set[str]]) -> list[str]:
  """Computes all upstream vulnerabilities for the given bug ID.
  The returned list contains all of the bug IDs that are upstream of the
  target bug ID, including transitive upstreams."""
  visited = set()

  target_bug_upstream = target_bug
  if not target_bug_upstream:
    return []
  to_visit = set(target_bug_upstream)
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    upstreams = set()
    if bug_id in bugs.keys():
      bug = bugs.get(bug_id)
      upstreams = set(bug)

    to_visit.update(upstreams - visited)

  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates.
  return sorted(visited)


def _create_group(bug_id, upstream_ids) -> osv.UpstreamGroup:
  """Creates a new upstream group in the datastore."""

  new_group = osv.UpstreamGroup(
      id=bug_id,
      db_id=bug_id,
      upstream_ids=upstream_ids,
      last_modified=datetime.datetime.now(datetime.UTC))
  new_group.put()
  _update_vuln_with_group(bug_id, new_group)

  return new_group


def _update_group(upstream_group: osv.UpstreamGroup,
                  upstream_ids: list) -> osv.UpstreamGroup | None:
  """Updates the upstream group in the datastore."""
  if len(upstream_ids) == 0:
    logging.info('Deleting upstream group due to too few bugs: %s',
                 upstream_ids)
    upstream_group.key.delete()
    _update_vuln_with_group(upstream_group.db_id, None)
    return None

  if upstream_ids == upstream_group.upstream_ids:
    return None

  upstream_group.upstream_ids = upstream_ids
  upstream_group.last_modified = datetime.datetime.now(datetime.UTC)
  upstream_group.put()
  _update_vuln_with_group(upstream_group.db_id, upstream_group)
  return upstream_group


def _update_vuln_with_group(vuln_id: str, upstream: osv.UpstreamGroup | None):
  """Updates the Vulnerability in Datastore & GCS with the new upstream group.
  If `upstream` is None, assumes a preexisting UpstreamGroup was just deleted.
  """
  # TODO!!: check if not test instance or tests
  if False:  # pylint: disable=using-constant-test
    return
  # Get the existing vulnerability first, so we can recalculate search_indices
  bucket = gcs.get_osv_bucket()
  pb_blob = bucket.get_blob(os.path.join(gcs.VULN_PB_PATH, vuln_id + '.pb'))
  if pb_blob is None:
    logging.error('vulnerability not in GCS - %s', vuln_id)
    # TODO(michaelkedar): send pub/sub message to reimport
    return
  try:
    vuln_proto = osv.vulnerability_pb2.Vulnerability.FromString(
        pb_blob.download_as_bytes())
  except Exception:
    logging.exception('failed to download %s protobuf from GCS', vuln_id)

  def transaction():
    vuln: osv.Vulnerability = osv.Vulnerability.get_by_id(vuln_id)
    if vuln is None:
      logging.error('vulnerability not in Datastore - %s', vuln_id)
      # TODO: Raise exception
      return
    if upstream is None:
      modified = datetime.datetime.now(datetime.UTC)
      upstream_group = []
    else:
      modified = upstream.last_modified
      upstream_group = upstream.upstream_ids
    vuln_proto.upstream[:] = upstream_group
    vuln_proto.modified.FromDatetime(modified)
    osv.ListedVulnerability.from_vulnerability(vuln_proto).put()
    vuln.modified = modified
    vuln.put()

  ndb.transaction(transaction)
  modified = vuln_proto.modified.ToDatetime(datetime.UTC)
  try:
    pb_blob.custom_time = modified
    pb_blob.upload_from_string(
        vuln_proto.SerializeToString(deterministic=True),
        content_type='application/octet-stream',
        if_generation_match=pb_blob.generation)
  except Exception:
    logging.exception('failed to upload %s protobuf to GCS', vuln_id)
    # TODO(michaelkedar): send pub/sub message to retry

  try:
    json_blob = bucket.blob(os.path.join(gcs.VULN_JSON_PATH, vuln_id + '.json'))
    json_blob.custom_time = modified
    json_data = json_format.MessageToJson(
        vuln_proto, preserving_proto_field_name=True, indent=None)
    json_blob.upload_from_string(json_data, content_type='application/json')
  except Exception:
    logging.exception('failed to upload %s json to GCS', vuln_id)
    # TODO(michaelkedar): send pub/sub message to retry


def compute_upstream_hierarchy(
    target_upstream_group: osv.UpstreamGroup,
    all_upstream_groups: dict[str, osv.UpstreamGroup]) -> None:
  """Computes all upstream vulnerabilities for the given bug ID.
  The returned list contains all of the bug IDs that are upstream of the
  target bug ID, including transitive upstreams in a map hierarchy.
  upstream_group:
        { db_id: bug id
          upstream_ids: list of upstream bug ids
          last_modified_date: date
          upstream_hierarchy: JSON string of upstream hierarchy
        }
  """

  # To convert to json, sets need to be converted to lists
  # and sorting is done for a more consistent outcome.
  def set_default(obj):
    if isinstance(obj, set):
      return list(sorted(obj))
    raise TypeError

  visited = set()
  upstream_map = {}
  to_visit = set([target_upstream_group.db_id])
  # BFS navigation through the upstream hierarchy of a given upstream group
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    upstream_group = all_upstream_groups.get(bug_id)
    if upstream_group is None:
      continue

    upstreams = set(upstream_group.upstream_ids)
    if not upstreams:
      continue
    for upstream in upstreams:
      if upstream not in visited and upstream not in to_visit:
        to_visit.add(upstream)
      else:
        if bug_id not in upstream_map:
          upstream_map[bug_id] = set([upstream])
        else:
          upstream_map[bug_id].add(upstream)
    # Add the immediate upstreams of the bug to the dict
    upstream_map[bug_id] = upstreams
    to_visit.update(upstreams - visited)

  # Ensure there are no duplicate entries where transitive vulns appear
  for k, v in upstream_map.items():
    if k is target_upstream_group.db_id:
      continue
    upstream_map[target_upstream_group
                 .db_id] = upstream_map[target_upstream_group.db_id] - v

  # Update the datastore entry if hierarchy has changed
  if upstream_map:
    upstream_json = json.dumps(upstream_map, default=set_default)
    if upstream_json == target_upstream_group.upstream_hierarchy:
      return
    target_upstream_group.upstream_hierarchy = upstream_json
    target_upstream_group.put()


def main():
  """Updates all upstream groups in the datastore by re-computing existing
  UpstreamGroups and creating new UpstreamGroups for un-computed bugs."""

  # Query for all bugs that have upstreams.
  updated_bugs = []
  logging.info('Retrieving bugs...')
  bugs_query = osv.Bug.query(osv.Bug.upstream_raw > '')

  bugs = defaultdict(set)
  for bug in bugs_query.iter(projection=[osv.Bug.db_id, osv.Bug.upstream_raw]):
    bugs[bug.db_id].add(bug.upstream_raw[0])
  logging.info('%s Bugs successfully retrieved', len(bugs))

  logging.info('Retrieving upstream groups...')
  upstream_groups = {
      group.db_id: group for group in osv.UpstreamGroup.query().iter()
  }
  logging.info('Upstream Groups successfully retrieved')

  for bug_id, bug in bugs.items():
    # Get the specific upstream_group ID
    upstream_group = upstream_groups.get(bug_id)
    # Recompute the transitive upstreams and compare with the existing group
    upstream_ids = compute_upstream(bug, bugs)
    if upstream_group:
      if upstream_ids == upstream_group.upstream_ids:
        continue
      # Update the existing UpstreamGroup
      new_upstream_group = _update_group(upstream_group, upstream_ids)
      if new_upstream_group is None:
        continue
      updated_bugs.append(new_upstream_group)
      upstream_groups[bug_id] = new_upstream_group
      logging.info('Upstream group updated for bug: %s', bug_id)
    else:
      # Create a new UpstreamGroup
      new_upstream_group = _create_group(bug_id, upstream_ids)
      logging.info('New upstream group created for bug: %s', bug_id)
      updated_bugs.append(new_upstream_group)
      upstream_groups[bug_id] = new_upstream_group

  for group in updated_bugs:
    # Recompute the upstream hierarchies
    compute_upstream_hierarchy(group, upstream_groups)
    logging.info('Upstream hierarchy updated for bug: %s', group.db_id)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('upstream')
  with _ndb_client.context():
    main()
