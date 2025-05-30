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
"""Mark bugs public."""

from __future__ import annotations

import logging
import sys
from typing import Any, Dict, List, Optional # Added necessary types

from google.cloud import ndb

# Assuming these are custom modules for interacting with Google Issue Tracker
from google_issue_tracker import client as issue_tracker_client # Aliased for clarity
from google_issue_tracker import issue_tracker # For IssueTracker class and IssueTrackerError

import osv.models # For osv.models.Bug, osv.models.AffectedCommits
import osv.logs # For osv.logs.setup_gcp_logging

# Global NDB client
_ndb_client: ndb.Client


def make_affected_commits_public(bug: osv.models.Bug) -> None:
  """Make related AffectedCommits entities public."""
  if not bug.key or not bug.key.id(): # Should not happen for valid Bug from datastore
      logging.error("Bug missing key or ID, cannot make AffectedCommits public.")
      return

  # osv.models.AffectedCommits needed
  affected_commits_query: ndb.Query[osv.models.AffectedCommits] = osv.models.AffectedCommits.query(
      osv.models.AffectedCommits.bug_id == bug.key.id()) # type: ignore[union-attr]

  current_affected_commits: osv.models.AffectedCommits # Type hint for loop variable
  for current_affected_commits in affected_commits_query:
    current_affected_commits.public = True
    # Write entities individually as they can be large.
    current_affected_commits.put()
  logging.info("Marked AffectedCommits public for Bug ID: %s", bug.key.id()) # type: ignore[union-attr]


def main() -> int:
  """Mark bugs public."""
  # Assuming client.build() returns the http client object expected by IssueTracker
  # The exact type of this client depends on the 'google-api-python-client' or similar.
  # Using Any if specific type is not readily available or too complex.
  # For now, let's assume it returns an object compatible with IssueTracker.
  # If issue_tracker_client.build() returns a specific type, use that.
  # Let's assume `issue_tracker.IssueTracker` takes this client object.
  # The type of `tracker_http_client` would be something like `googleapiclient.discovery.Resource`
  tracker_http_client: Any = issue_tracker_client.build()
  tracker = issue_tracker.IssueTracker(tracker_http_client)

  # Query for non-public Bug entities
  # osv.models.Bug needed
  bugs_to_check_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query( # Renamed query
      osv.models.Bug.public == False)  # noqa: E712

  bugs_to_make_public: List[osv.models.Bug] = [] # Renamed to_mark_public

  current_bug: osv.models.Bug # Type hint for loop variable, renamed bug
  for current_bug in bugs_to_check_query:
    # Bug.issue_id is StringProperty, so it's Optional[str] effectively if not required
    issue_id_str: Optional[str] = current_bug.issue_id # Renamed issue_id
    if not issue_id_str:
      logging.info('Missing issue_id for Bug ID: %s.', current_bug.key.id() if current_bug.key else "Unknown")
      continue

    try:
      # tracker.get_issue returns a Dict representing the issue resource
      issue_data: Dict[str, Any] = tracker.get_issue(issue_id_str) # Renamed issue
    except issue_tracker.IssueTrackerError:
      logging.error('Failed to get issue %s from Issue Tracker.', issue_id_str, exc_info=True)
      continue

    # Check access level from issue data
    # issueState and accessLimit might be missing, hence .get(..., {})
    issue_state: Dict[str, Any] = issue_data.get('issueState', {})
    access_limit: Dict[str, Any] = issue_state.get('accessLimit', {})
    access_level: Optional[str] = access_limit.get('accessLevel')

    if access_level == issue_tracker.IssueAccessLevel.LIMIT_NONE: # Publicly visible
      current_bug.public = True
      logging.info('Marking Bug ID %s as public (based on Issue ID %s).',
                   current_bug.key.id() if current_bug.key else "Unknown", issue_id_str)
      bugs_to_make_public.append(current_bug)
      # Also make associated AffectedCommits public
      make_affected_commits_public(current_bug)

  if bugs_to_make_public:
    ndb.put_multi(bugs_to_make_public)
    logging.info("Successfully updated %d Bug(s) to public.", len(bugs_to_make_public))
  else:
    logging.info("No bugs found to mark as public in this run.")

  return 0


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('make_bugs_public') # project_id inferred
  with _ndb_client.context():
    sys.exit(main())
