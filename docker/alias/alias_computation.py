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

from google.cloud import ndb

import osv
import osv.logs

bugs_map = {}
aliases_map = {}


def _update_group(bug_ids, alias_group):
  """Updates the alias group in the datastore."""
  if len(bug_ids) <= 1:
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
    return
  new_group = osv.AliasGroup(bug_ids=bug_ids)
  new_group.bug_ids.sort()
  new_group.last_modified = datetime.datetime.utcnow()
  new_group.put()


def _compute_bugs_ids(to_visit, visited):
  """Computes the bug IDs for the given set of aliases and bugs."""
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
  """Updates all alias groups in the datastore."""
  bugs = osv.Bug.query(osv.Bug.aliases > '').fetch()
  all_alias_group = osv.AliasGroup.query().fetch()

  for bug in bugs:
    bugs_map[bug.db_id] = bug.aliases
    for alias in bug.aliases:
      aliases_map.setdefault(alias, []).append(bug.db_id)

  visited = set()
  for alias_group in all_alias_group:
    to_visit = set(alias_group.bug_ids)
    bug_ids = _compute_bugs_ids(to_visit, visited)
    _update_group(bug_ids, alias_group)

  for bug_id in bugs_map:
    if bug_id not in visited:
      to_visit = {bug_id}
      bug_ids = _compute_bugs_ids(to_visit, visited)
      _create_alias_group(bug_ids)

  all_alias_group = osv.AliasGroup.query().fetch()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('alias')
  with _ndb_client.context():
    main()
