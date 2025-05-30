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
"""Generate impact requests."""

from __future__ import annotations

import datetime
import logging
import os
import sys
from typing import Dict, Optional # Added Dict, Optional

from google.cloud import ndb
from google.cloud import pubsub_v1

import osv.models # For NDB model types
import osv.logs # For osv.logs.setup_gcp_logging

_PROJECT_ID_ENV: Optional[str] = os.environ.get('GOOGLE_CLOUD_PROJECT')
if not _PROJECT_ID_ENV:
    raise RuntimeError("GOOGLE_CLOUD_PROJECT environment variable not set.")

_TASKS_TOPIC = f'projects/{_PROJECT_ID_ENV}/topics/tasks'

# Global NDB client
_ndb_client: ndb.Client


def _get_counter(year: Optional[int] = None) -> osv.models.IDCounter:
  """Get next Bug ID counter for the given year, or current year if None."""
  if year is None:
    year = datetime.datetime.now(datetime.UTC).year

  # NDB Key type can be Key[ModelKind]
  key: ndb.Key[osv.models.IDCounter] = ndb.Key(osv.models.IDCounter, year)

  counter: Optional[osv.models.IDCounter] = key.get()
  if counter:
    return counter

  # Create a new counter if one doesn't exist for this year
  logging.info("Creating new IDCounter for year %d.", year)
  new_counter = osv.models.IDCounter(id=year, next_id=1)
  # new_counter.put() # Should this be put here or by the caller after modification?
  # Original code implies it's put by the caller after next_id is used.
  # For safety, if it's meant to be created and immediately available, put here.
  # However, the original logic fetches, then uses, then puts. So this return is fine.
  return new_counter


def main() -> int:
  """Generate impact requests for RegressResults that don't have Bugs yet."""
  publisher = pubsub_v1.PublisherClient()
  # Stores IDCounter entities keyed by year (or None for default year logic)
  # Value is osv.models.IDCounter, not int.
  id_counters_cache: Dict[Optional[int], osv.models.IDCounter] = {} # Renamed counters

  # Query for all RegressResult entities
  regress_results_query: ndb.Query[osv.models.RegressResult] = osv.models.RegressResult.query() # Renamed

  current_regress_result: osv.models.RegressResult # Type hint for loop var, renamed
  for current_regress_result in regress_results_query:
    # Ensure key and id exist before using them
    if not current_regress_result.key or not current_regress_result.key.id():
        logging.warning("RegressResult missing key or ID: %s", current_regress_result)
        continue

    source_key_id: str = str(current_regress_result.key.id()) # Renamed key_id, ensure str

    if not current_regress_result.commit:
      logging.info('Missing commit info for RegressResult ID: %s.', source_key_id)
      continue

    # Check if a corresponding FixResult exists and has a commit
    # NDB Key type can be Key[ModelKind]
    fix_result_key: ndb.Key[osv.models.FixResult] = ndb.Key(osv.models.FixResult, source_key_id)
    fixed_result_obj: Optional[osv.models.FixResult] = fix_result_key.get() # Renamed fixed_result
    if not fixed_result_obj or not fixed_result_obj.commit:
      # Original log implies this is not a fatal error, just info.
      logging.info('FixedResult does not exist or lacks commit for source_id: %s.', source_key_id)
      # Continue processing even if FixResult is missing, as impact might still be relevant.

    # Check if a Bug already exists for this source_id (RegressResult key ID)
    # osv.models.Bug needed
    existing_bug_for_source: Optional[osv.models.Bug] = osv.models.Bug.query( # Renamed bug
        osv.models.Bug.source_id == source_key_id).get()
    if existing_bug_for_source:
      logging.info('Bug already exists (via source_id %s) for RegressResult ID: %s. OSV ID: %s',
                   source_key_id, source_key_id, existing_bug_for_source.id())
      continue

    # If RegressResult has an issue_id, check if a Bug already exists for that issue_id
    if current_regress_result.issue_id:
      existing_bug_for_issue: Optional[osv.models.Bug] = osv.models.Bug.query( # Renamed bug
          osv.models.Bug.issue_id == current_regress_result.issue_id).get()
      if existing_bug_for_issue:
        logging.info('Bug already exists (via issue_id %s) for RegressResult ID: %s. OSV ID: %s',
                     current_regress_result.issue_id, source_key_id, existing_bug_for_issue.id())
        continue

    # Determine the year for ID allocation based on RegressResult timestamp
    year_for_id: Optional[int] = None # Renamed id_year
    if current_regress_result.timestamp:
      year_for_id = current_regress_result.timestamp.year
    # If no timestamp, year_for_id remains None, _get_counter will use current year.

    # Get or create IDCounter for the determined year
    year_counter: osv.models.IDCounter = id_counters_cache.get(year_for_id) # Renamed counter
    if not year_counter:
      year_counter = _get_counter(year_for_id)
      id_counters_cache[year_for_id] = year_counter

    try:
      # counter.key.id() should be the year (int). counter.next_id is int.
      # Ensure key is not None before accessing id(). _get_counter returns persisted or new entity.
      # New entities get key upon first put, or if ID is pre-assigned (which it is here: `year`).
      counter_year_id = year_counter.key.id() if year_counter.key else year_for_id
      if counter_year_id is None: # Should not happen if year_for_id or current year is used.
          logging.error("IDCounter key ID is None for year %s. Skipping.", year_for_id)
          continue

      allocated_osv_id: str = f'OSV-{counter_year_id}-{year_counter.next_id}' # Renamed cur_id
      logging.info('Allocating OSV ID %s for RegressResult ID %s.', allocated_osv_id, source_key_id)
      year_counter.next_id += 1

      # Create the new Bug entity (status UNPROCESSED)
      new_bug_obj = osv.models.Bug( # Renamed bug
          db_id=allocated_osv_id, # Store the allocated OSV ID
          timestamp=datetime.datetime.now(datetime.UTC), # Creation timestamp
          public=False, # Initially not public
          source_id=source_key_id, # Link to the RegressResult/FixResult key ID
          status=osv.models.BugStatus.UNPROCESSED # Initial status
      )
      new_bug_obj.put() # Persist the new Bug entity

      logging.info('Requesting impact analysis for new OSV ID %s (from source %s).',
                   allocated_osv_id, source_key_id)
      publisher.publish(
          _TASKS_TOPIC,
          data=b'', # No data payload needed, info is in attributes
          type='impact', # Task type
          source_id=source_key_id, # Original source ID (RegressResult ID)
          allocated_id=allocated_osv_id # Newly allocated OSV ID
      )
    finally:
      # Persist the updated IDCounter (with incremented next_id)
      year_counter.put()

  return 0


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('process_results') # project_id inferred
  with _ndb_client.context():
    sys.exit(main())
