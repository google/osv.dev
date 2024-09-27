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

import logging
import sys
from google.cloud import ndb
import requests

from google_issue_tracker import client
from google_issue_tracker import issue_tracker
import osv
import osv.logs

_MONORAIL_ACCOUNT = 'service@oss-vdb.iam.gserviceaccount.com'


def make_affected_commits_public(bug):
  """Make related AffectedCommits entities public."""
  query = osv.AffectedCommits.query(osv.AffectedCommits.bug_id == bug.key.id())
  for affected_commits in query:
    affected_commits.public = True
    # Write entities individually as they can be large.
    affected_commits.put()


def main():
  """Mark bugs public."""
  tracker = issue_tracker.IssueTracker(client.build())
  query = osv.Bug.query(osv.Bug.public == False)  # pylint: disable=singleton-comparison

  to_mark_public = []
  for bug in query:
    issue_id = bug.issue_id
    if not issue_id:
      logging.info('Missing issue_id for %s.', bug.key.id())
      continue

    try:
      issue = tracker.get_issue(issue_id)
    except issue_tracker.IssueTrackerError:
      logging.error('Failed to get issue %s.', issue_id)
      continue

    if (issue['issueState'].get(
        'accessLimit',
        {}).get('accessLevel') == issue_tracker.IssueAccessLevel.LIMIT_NONE):
      bug.public = True
      logging.info('Marking %s as public.', bug.key.id())
      to_mark_public.append(bug)
      make_affected_commits_public(bug)

  if to_mark_public:
    ndb.put_multi(to_mark_public)

  return 0


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('make_bugs_public')
  with _ndb_client.context():
    sys.exit(main())
