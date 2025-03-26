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


def _update_group(bug_ids, alias_group):
  """Updates the alias group in the datastore."""
  if len(bug_ids) <= 1:
    logging.info('Deleting alias group due to too few bugs: %s', bug_ids)
    alias_group.key.delete()
    return
  if len(bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Deleting alias group due to too many bugs: %s', bug_ids)
    alias_group.key.delete()
    return

  if bug_ids == alias_group.bug_ids:
    return

  alias_group.bug_ids = bug_ids
  alias_group.last_modified = datetime.datetime.utcnow()
  alias_group.put()


def _create_alias_group(bug_ids):
  """Creates a new alias group in the datastore."""
  if len(bug_ids) <= 1:
    logging.info('Skipping alias group creation due to too few bugs: %s',
                 bug_ids)
    return
  if len(bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Skipping alias group creation due to too many bugs: %s',
                 bug_ids)
    return

  new_group = osv.AliasGroup(bug_ids=bug_ids)
  new_group.last_modified = datetime.datetime.now()
  new_group.put()


def _compute_aliases(bug_id, visited, bug_aliases):
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

    aliases = bug_aliases.get(bug_id, set())
    to_visit.update(aliases - visited)

  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates to the groups.
  return sorted(bug_ids)


def main():
  """Updates all alias groups in the datastore by re-computing existing
  AliasGroups and creating new AliasGroups for un-computed bugs."""

  # Query for all bugs that have aliases.
  # Use (> '' OR < '') instead of (!= '') / (> '') to de-duplicate results
  # and avoid datastore emulator problems, see issue #2093
  bugs = osv.Bug.query(ndb.OR(osv.Bug.aliases > '', osv.Bug.aliases < ''))
  all_alias_group = osv.AliasGroup.query()
  allow_list = {
      allow_entry.bug_id for allow_entry in osv.AliasAllowListEntry.query()
  }
  deny_list = {
      deny_entry.bug_id for deny_entry in osv.AliasDenyListEntry.query()
  }

  # Mapping of ID to a set of all aliases for that bug,
  # including its raw aliases and bugs that it is referenced in as an alias.
  bug_aliases = {}

  # For each bug, add its aliases to the maps and ignore invalid bugs.
  for bug in bugs:
    if bug.db_id in deny_list:
      continue
    if len(bug.aliases) > VULN_ALIASES_LIMIT and bug.db_id not in allow_list:
      logging.info('%s has too many listed aliases, skipping computation.',
                   bug.db_id)
      continue
    if bug.status != osv.BugStatus.PROCESSED:
      continue
    for alias in bug.aliases:
      bug_aliases.setdefault(bug.db_id, set()).add(alias)
      bug_aliases.setdefault(alias, set()).add(bug.db_id)

  visited = set()

  # For each alias group, re-compute the bug IDs in the group and update the
  # group with the computed bug IDs.
  for alias_group in all_alias_group:
    bug_id = alias_group.bug_ids[0]  # AliasGroups contain more than one bug.
    # If the bug has already been counted in a different alias group,
    # we delete the original one to merge two alias groups.
    if bug_id in visited:
      alias_group.key.delete()
      continue
    bug_ids = _compute_aliases(bug_id, visited, bug_aliases)
    _update_group(bug_ids, alias_group)

  # For each bug ID that has not been visited, create new alias groups.
  for bug_id in bug_aliases:
    if bug_id not in visited:
      bug_ids = _compute_aliases(bug_id, visited, bug_aliases)
      _create_alias_group(bug_ids)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('alias')
  with _ndb_client.context():
    main()
