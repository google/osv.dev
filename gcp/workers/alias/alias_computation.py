#!/usr/bin/env python3
# Copyright 2023 Google LLC
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
"""OSV alias computation."""
from __future__ import annotations

import datetime
import logging
from typing import Dict, List, Set

from google.cloud import ndb

import osv.models # Import models directly for specific types
import osv.logs

ALIAS_GROUP_VULN_LIMIT = 32
VULN_ALIASES_LIMIT = 5

# Global NDB client instance, initialized in if __name__ == '__main__' or by importer.
_ndb_client: ndb.Client


def _update_group(bug_ids: List[str], alias_group: osv.models.AliasGroup) -> None:
  """Updates the alias group in the datastore."""
  # Deduplicate and sort bug_ids before checks and assignment for consistency
  sorted_bug_ids = sorted(list(set(bug_ids)))

  if len(sorted_bug_ids) <= 1:
    logging.info('Deleting alias group due to too few unique bugs: %s (%s)',
                 alias_group.key.id() if alias_group.key else "Unknown Key", sorted_bug_ids)
    if alias_group.key: # Ensure key exists before deleting
        alias_group.key.delete()
    return
  if len(sorted_bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Deleting alias group due to too many unique bugs: %s (%s)',
                 alias_group.key.id() if alias_group.key else "Unknown Key", sorted_bug_ids)
    if alias_group.key:
        alias_group.key.delete()
    return

  # alias_group.bug_ids should also be consistently sorted if it was set by this logic before.
  # For safety, sort it too if it's not None.
  current_group_bug_ids = sorted(list(set(alias_group.bug_ids))) if alias_group.bug_ids else []

  if sorted_bug_ids == current_group_bug_ids:
    return # No change needed

  alias_group.bug_ids = sorted_bug_ids
  alias_group.last_modified = datetime.datetime.now(datetime.UTC)
  alias_group.put()
  logging.info('Updated alias group %s with bug_ids: %s',
               alias_group.key.id() if alias_group.key else "Unknown Key", sorted_bug_ids)


def _create_alias_group(bug_ids: List[str]) -> None:
  """Creates a new alias group in the datastore."""
  # Deduplicate and sort bug_ids before checks and creation
  sorted_bug_ids = sorted(list(set(bug_ids)))

  if len(sorted_bug_ids) <= 1:
    logging.info('Skipping alias group creation due to too few unique bugs: %s',
                 sorted_bug_ids)
    return
  if len(sorted_bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Skipping alias group creation due to too many unique bugs: %s',
                 sorted_bug_ids)
    return

  new_group = osv.models.AliasGroup(bug_ids=sorted_bug_ids)
  new_group.last_modified = datetime.datetime.now(datetime.UTC)
  new_group.put()
  logging.info('Created new alias group with bug_ids: %s (Key: %s)',
               sorted_bug_ids, new_group.key.id() if new_group.key else "Unknown")


def _compute_aliases(initial_bug_id: str, # Renamed bug_id to initial_bug_id
                     visited: Set[str],
                     bug_aliases_map: Dict[str, Set[str]] # Renamed bug_aliases
                    ) -> List[str]:
  """Computes all aliases for the given initial_bug_id.
  The returned list contains the initial_bug_id itself, all the IDs from its
  raw aliases, all the IDs of bugs that have the current bug as an alias,
  and repeats for every bug encountered transitively.
  Modifies `visited` in place.
  """
  to_visit_stack: List[str] = [initial_bug_id] # Renamed to_visit to to_visit_stack for clarity (it's used as a stack)
  # Using a list for collected_bug_ids to maintain some order if needed, though it's sorted at the end.
  collected_bug_ids: List[str] = [] # Renamed bug_ids

  while to_visit_stack:
    current_bug_id: str = to_visit_stack.pop() # Renamed bug_id to current_bug_id
    if current_bug_id in visited:
      continue

    visited.add(current_bug_id)
    collected_bug_ids.append(current_bug_id)

    # Get related aliases from the precomputed map
    # Ensure bug_aliases_map.get returns an empty set if key not found
    related_aliases: Set[str] = bug_aliases_map.get(current_bug_id, set())
    # Add newly found aliases that haven't been visited to the stack
    for alias_id in related_aliases: # Renamed aliases to related_aliases
        if alias_id not in visited:
            to_visit_stack.append(alias_id)


  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates to the groups.
  return sorted(list(set(collected_bug_ids))) # Deduplicate before sort


def main() -> None:
  """Updates all alias groups in the datastore by re-computing existing
  AliasGroups and creating new AliasGroups for un-computed bugs."""

  # Query for all bugs that have aliases.
  # osv.models.Bug needed. ndb.OR for NDB query.
  bugs_with_aliases_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query( # Renamed bugs
      ndb.OR(osv.models.Bug.aliases > '', osv.models.Bug.aliases < '')) # type: ignore[operator] # NDB OR filter

  all_alias_groups_query: ndb.Query[osv.models.AliasGroup] = osv.models.AliasGroup.query() # Renamed all_alias_group

  # Fetch allow and deny lists once
  # osv.models.AliasAllowListEntry, osv.models.AliasDenyListEntry needed
  allow_list: Set[str] = {
      allow_entry.bug_id for allow_entry in osv.models.AliasAllowListEntry.query() if allow_entry.bug_id
  }
  deny_list: Set[str] = {
      deny_entry.bug_id for deny_entry in osv.models.AliasDenyListEntry.query() if deny_entry.bug_id
  }

  # Mapping of ID to a set of all its direct and indirect aliases.
  bug_aliases_map: Dict[str, Set[str]] = {} # Renamed bug_aliases

  # Populate bug_aliases_map from all bugs
  # NDB query iteration
  current_bug: osv.models.Bug
  for current_bug in bugs_with_aliases_query: # Renamed bug
    if not current_bug.db_id: continue # Should not happen for valid Bug entities

    if current_bug.db_id in deny_list:
      continue

    # Ensure bug.aliases is not None before len()
    bug_aliases_list = current_bug.aliases or []
    if len(bug_aliases_list) > VULN_ALIASES_LIMIT and current_bug.db_id not in allow_list:
      logging.info('%s has too many listed aliases (%d), skipping computation.',
                   current_bug.db_id, len(bug_aliases_list))
      continue

    # Ensure bug.status is compared against enum's value if it's an IntEnum field
    # If BugStatus is an NDB EnumProperty(enum_class=...), direct comparison is fine.
    # osv.models.BugStatus.PROCESSED is an IntEnum member.
    if current_bug.status != osv.models.BugStatus.PROCESSED:
      continue

    # Add bug's own aliases to the map
    for alias_id in bug_aliases_list: # Renamed alias
      if not alias_id: continue # Skip empty alias strings
      bug_aliases_map.setdefault(current_bug.db_id, set()).add(alias_id)
      bug_aliases_map.setdefault(alias_id, set()).add(current_bug.db_id) # Bidirectional link

  # Set of bug IDs already processed and included in an AliasGroup
  visited_bug_ids: Set[str] = set() # Renamed visited

  # Re-compute existing alias groups
  current_alias_group: osv.models.AliasGroup
  for current_alias_group in all_alias_groups_query: # Renamed alias_group
    # AliasGroup.bug_ids should not be empty by definition of a valid group.
    if not current_alias_group.bug_ids: # Should not happen
        if current_alias_group.key: current_alias_group.key.delete()
        continue

    # Pick a representative bug_id from the group to re-compute the full set.
    # Sorting bug_ids helps in picking a canonical representative if needed,
    # but any ID from the group should yield the same full alias set.
    # For stability, let's sort and pick first if not already sorted.
    # (Assuming bug_ids in AliasGroup are already sorted as per _update_group/_create_alias_group)
    representative_bug_id: str = current_alias_group.bug_ids[0] # Renamed bug_id

    if representative_bug_id in visited_bug_ids:
      # This group is now redundant or a sub-group of an already processed one. Delete it.
      logging.info("Deleting redundant alias group: %s (representative %s already visited)",
                   current_alias_group.key.id() if current_alias_group.key else "Unknown Key", representative_bug_id)
      if current_alias_group.key: current_alias_group.key.delete()
      continue

    # Compute the full set of transitive aliases starting from this representative.
    # _compute_aliases will update visited_bug_ids.
    computed_bug_ids: List[str] = _compute_aliases(representative_bug_id, visited_bug_ids, bug_aliases_map) # Renamed bug_ids
    _update_group(computed_bug_ids, current_alias_group)

  # Create new alias groups for any bug_ids not yet visited (i.e., not part of any existing group).
  for bug_id_from_map in bug_aliases_map: # Renamed bug_id
    if bug_id_from_map not in visited_bug_ids:
      # This bug_id (and its related aliases) were not part of any existing AliasGroup.
      # Compute its full alias set and create a new group.
      computed_bug_ids_for_new_group: List[str] = _compute_aliases(bug_id_from_map, visited_bug_ids, bug_aliases_map) # Renamed bug_ids
      _create_alias_group(computed_bug_ids_for_new_group)


if __name__ == '__main__':
  # This global assignment is okay for a script, but for modules, client should be managed.
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('alias') # project_id will be inferred by setup_gcp_logging
  # Establish NDB context for main() execution if it uses NDB operations directly or indirectly.
  with _ndb_client.context():
    main()
