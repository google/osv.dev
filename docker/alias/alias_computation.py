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
import datetime
import logging

from google.cloud import ndb

import osv
import osv.logs

ALIAS_GROUP_VULN_LIMIT = 32
VULN_ALIASES_LIMIT = 5

bugs_map = {}
aliases_map = {}


def _update_group(bug_ids, alias_group):
  """Updates the alias group in the datastore."""
  if len(bug_ids) <= 1 or len(bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Deleting alias group due to invalid number of bugs: %s',
                 bug_ids)
    alias_group.key.delete()
    return True

  if bug_ids == alias_group.bug_ids:
    return False

  alias_group.bug_ids = bug_ids
  alias_group.last_modified = datetime.datetime.utcnow()
  alias_group.put()
  return True


def _create_alias_group(bug_ids):
  """Creates a new alias group in the datastore."""
  if len(bug_ids) <= 1 or len(bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info(
        'Skipping alias group creation due to invalid number of bugs: %s',
        bug_ids)
    return
  new_group = osv.AliasGroup(bug_ids=bug_ids)
  new_group.last_modified = datetime.datetime.utcnow()
  new_group.put()


def _compute_aliases(bug_id, visited):
  """Computes all aliases for the given bug ID.
  The returned list contains the bug ID itself, all the IDs from the bug's
  raw aliases, all the IDs of bugs that have the current bug as an alias,
  and repeat for every bug encountered here."""
  to_visit = {bug_id}
  bug_ids = []
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    bug_ids.append(bug_id)

    aliases = bugs_map.get(bug_id, [])
    bugs_of_alias = aliases_map.get(bug_id, [])
    to_visit.update(set(bugs_of_alias + aliases) - visited)

  return sorted(bug_ids)


def main():
  """Updates all alias groups in the datastore by re-computing existing
  AliasGroups and creating new AliasGroups for un-computed bugs."""

  # Query for all bugs that have aliases.
  bugs = osv.Bug.query(osv.Bug.aliases > '')
  all_alias_group = osv.AliasGroup.query()
  allow_list = set(osv.AliasAllowListEntry.query())
  deny_list = set(osv.AliasDenyListEntry.query())

  # For each bug, add its aliases to the maps and ignore invalid bugs.
  for bug in bugs:
    if bug.db_id not in allow_list and (bug.db_id in deny_list or
                                        len(bug.aliases) > VULN_ALIASES_LIMIT):
      logging.info('%s has too many listed aliases, skipping computation.',
                   bug.db_id)
      continue
    if bug.withdrawn:
      continue
    bugs_map[bug.db_id] = bug.aliases
    for alias in bug.aliases:
      aliases_map.setdefault(alias, []).append(bug.db_id)

  visited = set()

  # For each alias group, re-compute the bug IDs in the group and update the
  # group with the computed bug IDs.
  # If the group has already been updated, create new alias groups for others.
  # (It happens when splitting an alias group into multiple).
  for alias_group in all_alias_group:
    updated = False
    for bug_id in alias_group.bug_ids:
      if bug_id in visited:
        continue
      bug_ids = _compute_aliases(bug_id, visited)
      if not updated:
        updated = _update_group(bug_ids, alias_group)
      else:
        _create_alias_group(bug_ids)

  # For each bug ID that has not been visited, create new alias groups.
  for bug_id in bugs_map:
    if bug_id not in visited:
      bug_ids = _compute_aliases(bug_id, visited)
      _create_alias_group(bug_ids)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('alias')
  with _ndb_client.context():
    main()
