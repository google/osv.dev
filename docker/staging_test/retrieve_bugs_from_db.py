#!/usr/bin/env python3
# Copyright 2024 Google LLC
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
"""Fetch Bugs from from datastore"""

import logging
import os
import random
import json

import osv
import osv.logs

from google.cloud import ndb

GCP_PROJECT = 'oss-vdb-test'
BUG_DIR = '/staging_testing/all_bugs'

def format_bug_for_output(bug: osv.Bug) -> dict[str, any]:
  """Outputs ndb bug query results to JSON file

  Args:
    bug: an `osv.Bug` queried from ndb.

  Returns:
    A dict storing all the important `Bug` fields that we want to use later
  """

  affected_fuzzy = None
  # Store one version for use as the query version later.
  if len(bug.affected_fuzzy) > 0:
    version_index = random.randrange(len(bug.affected_fuzzy))
    affected_fuzzy = bug.affected_fuzzy[version_index]

  return {
      'db_id': bug.db_id,
      'purl': bug.purl,
      'project': bug.project,
      'ecosystem': bug.ecosystem,
      'affected_fuzzy': affected_fuzzy
  }


def get_bugs_from_datastore() -> None:
  """Gets all bugs from the datastore and writes to `BUG_DIR`."""

  entries_per_file = 10000  # amount of bugs per file
  batch_size = 1000
  file_counter = 0
  os.makedirs(BUG_DIR, exist_ok=True)

  def write_to_json():
    """Writes to a new JSON file."""
    file_name = f'{BUG_DIR}/all_bugs_{file_counter}.json'
    with open(file_name, 'w+') as f:
      json.dump(results, f, indent=2)
    logging.info(f'Saved {total_entries} entries to {file_name}')

  with ndb.Client(project=GCP_PROJECT).context():
    query = osv.Bug.query()
    query = query.filter(osv.Bug.status == osv.BugStatus.PROCESSED,
                         osv.Bug.public == True)  # pylint: disable=singleton-comparison
    logging.info(f'Querying {query}')

    results = []
    total_entries = 0
    next_cursor = None

    while True:
      bugs, next_cursor, has_more = query.fetch_page(
          page_size=batch_size, start_cursor=next_cursor)
      if not has_more:
        break

      logging.info(f'fetching {batch_size} entries.')
      results.extend([format_bug_for_output(bug) for bug in bugs])
      total_entries += len(bugs)

      # Write bugs to separate files in case the query fails or times out.
      if total_entries >= entries_per_file:
        write_to_json()

        # Reset for the next file
        results = []
        total_entries = 0
        file_counter += 1

    # Write any remaining entries to the last file
    if results:
      write_to_json()

  logging.info(f'All results saved to {BUG_DIR}.')

def main() -> None:
  osv.logs.setup_gcp_logging('staging-test')
  if not os.path.exists(BUG_DIR):
    # This will take around 10 mins
    get_bugs_from_datastore()
    logging.info('Fetching data finished.')
  else:
    logging.info(f'{BUG_DIR} exists, skipping fetching.')

if __name__ == "__main__":
  main()