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
from __future__ import annotations

import datetime
import json
import logging
from collections import defaultdict
from typing import Any, Dict, List, Optional, Set

from google.cloud import ndb

import osv.models # Import models for specific types
import osv.logs

# Global NDB client instance
_ndb_client: ndb.Client


def compute_upstream(
    target_bug_direct_upstream_ids: Set[str],
    all_bugs_to_direct_upstreams_map: Dict[str, Set[str]]
) -> List[str]:
  """Computes all transitive upstream vulnerabilities for a given set of direct upstream IDs.

  Args:
    target_bug_direct_upstream_ids: A set of bug IDs that are direct upstreams of the target bug.
    all_bugs_to_direct_upstreams_map: A dictionary mapping every known bug ID to a set of its direct upstream IDs.

  Returns:
    A sorted list of all unique transitive upstream bug IDs.
  """
  visited_ids: Set[str] = set()
  to_visit_stack: List[str] = list(target_bug_direct_upstream_ids)

  if not to_visit_stack:
    return []

  while to_visit_stack:
    current_bug_id: str = to_visit_stack.pop()
    if current_bug_id in visited_ids:
      continue

    visited_ids.add(current_bug_id)

    direct_upstreams_of_current: Set[str] = all_bugs_to_direct_upstreams_map.get(current_bug_id, set())

    for upstream_id in direct_upstreams_of_current:
        if upstream_id not in visited_ids:
            to_visit_stack.append(upstream_id)

  return sorted(list(visited_ids))


def _create_group(bug_id: str, upstream_ids: List[str]) -> osv.models.UpstreamGroup:
  """Creates a new upstream group in the datastore."""
  sorted_unique_upstream_ids = sorted(list(set(upstream_ids)))

  new_group = osv.models.UpstreamGroup(
      id=bug_id,
      db_id=bug_id,
      upstream_ids=sorted_unique_upstream_ids,
      last_modified=datetime.datetime.now(datetime.UTC)
  )
  new_group.put()
  logging.info('Created UpstreamGroup for %s with upstreams: %s', bug_id, sorted_unique_upstream_ids)
  return new_group


def _update_group(upstream_group: osv.models.UpstreamGroup,
                  upstream_ids: List[str]) -> Optional[osv.models.UpstreamGroup]:
  """Updates the upstream group in the datastore. Returns None if no update or group deleted."""
  sorted_unique_upstream_ids = sorted(list(set(upstream_ids)))

  if not sorted_unique_upstream_ids:
    logging.info('Deleting upstream group for %s due to no valid upstream IDs.', upstream_group.db_id)
    if upstream_group.key:
        upstream_group.key.delete()
    return None

  current_group_upstream_ids = sorted(list(set(upstream_group.upstream_ids or [])))
  if sorted_unique_upstream_ids == current_group_upstream_ids:
    return None

  upstream_group.upstream_ids = sorted_unique_upstream_ids
  upstream_group.last_modified = datetime.datetime.now(datetime.UTC)
  upstream_group.put()
  logging.info('Updated UpstreamGroup for %s with upstreams: %s', upstream_group.db_id, sorted_unique_upstream_ids)
  return upstream_group


def compute_upstream_hierarchy(
    target_upstream_group: osv.models.UpstreamGroup,
    all_upstream_groups_map: Dict[str, osv.models.UpstreamGroup]
) -> None:
  """Computes and updates the transitive upstream hierarchy for target_upstream_group.
  The hierarchy is stored as a JSON string in target_upstream_group.upstream_hierarchy.
  """

  def set_to_sorted_list_default(obj: Any) -> List[Any]:
    if isinstance(obj, set):
      try:
        return list(sorted(list(obj)))
      except TypeError:
        return list(obj)
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable (or set for custom handler)")

  transitive_upstream_map: Dict[str, Set[str]] = {}

  if not target_upstream_group.db_id or not target_upstream_group.upstream_ids:
      if target_upstream_group.upstream_hierarchy is not None:
          target_upstream_group.upstream_hierarchy = None
          target_upstream_group.put()
      return

  all_transitive_upstreams_for_target: Set[str] = set(target_upstream_group.upstream_ids or [])

  for current_bug_id in all_transitive_upstreams_for_target:
    current_bug_upstream_group = all_upstream_groups_map.get(current_bug_id)
    if not current_bug_upstream_group or not current_bug_upstream_group.upstream_ids:
      continue

    relevant_direct_upstreams = set(current_bug_upstream_group.upstream_ids) & all_transitive_upstreams_for_target

    if relevant_direct_upstreams:
      transitive_upstream_map[current_bug_id] = relevant_direct_upstreams

  if transitive_upstream_map:
    serializable_upstream_map: Dict[str, List[str]] = {
        k: list(sorted(list(v))) for k, v in transitive_upstream_map.items()
    }
    upstream_json_str = json.dumps(serializable_upstream_map)

    if upstream_json_str == target_upstream_group.upstream_hierarchy:
      return

    target_upstream_group.upstream_hierarchy = upstream_json_str
    target_upstream_group.last_modified = datetime.datetime.now(datetime.UTC)
    target_upstream_group.put()
    logging.info("Updated upstream_hierarchy for %s", target_upstream_group.db_id)
  elif target_upstream_group.upstream_hierarchy is not None:
    target_upstream_group.upstream_hierarchy = None
    target_upstream_group.last_modified = datetime.datetime.now(datetime.UTC)
    target_upstream_group.put()
    logging.info("Cleared upstream_hierarchy for %s as it's now empty.", target_upstream_group.db_id)


def main() -> None:
  """Updates all upstream groups in the datastore by re-computing existing
  UpstreamGroups and creating new UpstreamGroups for un-computed bugs."""

  updated_upstream_groups: List[osv.models.UpstreamGroup] = []
  logging.info('Retrieving bugs with upstream_raw field set...')
  bugs_with_upstreams_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query(
      osv.models.Bug.upstream_raw > '') # type: ignore[operator]

  all_bugs_to_direct_upstreams_map: Dict[str, Set[str]] = defaultdict(set)

  current_bug_projection: osv.models.Bug
  for current_bug_projection in bugs_with_upstreams_query.iter(
      projection=[osv.models.Bug.db_id, osv.models.Bug.upstream_raw]):
    if not current_bug_projection.db_id or not current_bug_projection.upstream_raw:
      continue

    all_bugs_to_direct_upstreams_map[current_bug_projection.db_id].update(current_bug_projection.upstream_raw)
  logging.info('%s Bugs with upstream_raw data successfully retrieved and mapped.', len(all_bugs_to_direct_upstreams_map))

  logging.info('Retrieving all existing UpstreamGroup entities...')
  existing_upstream_groups_map: Dict[str, osv.models.UpstreamGroup] = {
      group.db_id: group for group in osv.models.UpstreamGroup.query().iter() if group.db_id
  }
  logging.info('%s UpstreamGroup entities successfully retrieved.', len(existing_upstream_groups_map))

  for bug_id_str, direct_upstream_ids_set in all_bugs_to_direct_upstreams_map.items():
    existing_upstream_group: Optional[osv.models.UpstreamGroup] = existing_upstream_groups_map.get(bug_id_str)

    transitive_upstream_ids: List[str] = compute_upstream(
        direct_upstream_ids_set, all_bugs_to_direct_upstreams_map)

    updated_group: Optional[osv.models.UpstreamGroup] = None

    if existing_upstream_group:
      updated_group = _update_group(existing_upstream_group, transitive_upstream_ids)
      if updated_group:
        logging.info('UpstreamGroup updated for bug: %s', bug_id_str)
    else:
      if transitive_upstream_ids:
          updated_group = _create_group(bug_id_str, transitive_upstream_ids)
          logging.info('New UpstreamGroup created for bug: %s', bug_id_str)
      else:
          logging.info('No transitive upstreams for bug: %s, no group created.', bug_id_str)

    if updated_group:
      updated_upstream_groups.append(updated_group)
      existing_upstream_groups_map[bug_id_str] = updated_group

  for group_to_process_hierarchy in updated_upstream_groups:
    compute_upstream_hierarchy(group_to_process_hierarchy, existing_upstream_groups_map)

  logging.info("Upstream computation and hierarchy update complete.")


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('upstream')
  with _ndb_client.context():
    main()
