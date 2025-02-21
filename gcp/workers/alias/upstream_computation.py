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
"""OSV Upstream relation computation."""

import datetime
from google.cloud import ndb

import osv
import osv.logs

import logging


def compute_upstream(target_bug_id, bugs):
  """Computes all upstream vulnerabilities for the given bug ID.
  The returned list contains all of the bug IDs that are upstream of the
  target bug ID, including transitive upstreams."""
  visited = set()
  target_bug_upstream = bugs[target_bug_id]
  if not target_bug_upstream:
    return []
  to_visit = set(target_bug_upstream)
  bug_ids = []
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    bug_ids.append(bug_id)
    upstreams = set()
    if bug_id in bugs.keys():
      upstreams = set(bugs[bug_id])
    to_visit.update(upstreams - visited)

  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates.
  return sorted(bug_ids)


def _create_group(bug_id, upstream_ids):
  """Creates a new upstream group in the datastore."""

  new_group = osv.UpstreamGroup(db_id=bug_id)
  new_group.upstream_ids = upstream_ids
  new_group.last_modified = datetime.datetime.now()
  new_group.put()


def _update_group(upstream_group, upstream_ids: list):
  """Updates the alias group in the datastore."""
  if len(upstream_ids) < 1:
    logging.info('Deleting alias group due to too few bugs: %s', upstream_ids)
    upstream_group.key.delete()
    return

  if upstream_ids == upstream_group.upstream_ids:
    return

  upstream_group.upstream_ids = upstream_ids
  upstream_group.last_modified = datetime.datetime.now()
  upstream_group.put()


def main():
  """Updates all upstream groups in the datastore by re-computing existing
  UpstreamGroups and creating new UpstreamGroups for un-computed bugs."""

  # Query for all bugs that have upstreams.
  # Use (> '' OR < '') instead of (!= '') / (> '') to de-duplicate results
  # and avoid datastore emulator problems, see issue #2093
  bugs = osv.Bug.query(ndb.OR(osv.Bug.upstream > '', osv.Bug.upstream < ''))

  all_upstream_group = osv.UpstreamGroup.query()

  # for every bug, check if it has an UpstreamGroup.
  for bug in bugs:
    # check if the db key is also a db_id in all_upstream_group
    b = all_upstream_group.filter(osv.UpstreamGroup.db_id == bug.db_id)
    if b:
      #recompute the transitive upstreams and compare with the existing group
      upstream_ids = compute_upstream(bug.db_id, bugs)
      _update_group(b, upstream_ids)
    else:
      # Create a new UpstreamGroup
      upstream_ids = compute_upstream(bug.db_id, bugs)
      _create_group(bug, upstream_ids)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('upstream')
  with _ndb_client.context():
    main()
