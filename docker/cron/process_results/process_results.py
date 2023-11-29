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

import datetime
import logging
import os
import sys
from google.cloud import ndb
from google.cloud import pubsub_v1

import osv

_TASKS_TOPIC = 'projects/{project}/topics/{topic}'.format(
    project=os.environ['GOOGLE_CLOUD_PROJECT'], topic='tasks')


def _get_counter(year=None):
  """Get next Bug ID."""
  if year is None:
    year = datetime.datetime.utcnow().year

  key = ndb.Key(osv.IDCounter, year)

  counter = key.get()
  if counter:
    return counter

  return osv.IDCounter(id=year, next_id=1)


def main():
  """Generate impact requests."""
  publisher = pubsub_v1.PublisherClient()
  counters = {}

  for regress_result in osv.RegressResult.query():
    key_id = regress_result.key.id()
    if not regress_result.commit:
      logging.info('Missing commit info for %s.', key_id)
      continue

    fixed_result = ndb.Key(osv.FixResult, key_id).get()
    if not fixed_result or not fixed_result.commit:
      logging.info('Fixed result does not exist for %s.', key_id)

    bug = osv.Bug.query(osv.Bug.source_id == key_id).get()
    if bug:
      logging.info('Bug already exists for %s.', key_id)
      continue

    if regress_result.issue_id:
      bug = osv.Bug.query(osv.Bug.issue_id == regress_result.issue_id).get()
      if bug:
        logging.info('Bug already exists for issue %s.',
                     regress_result.issue_id)
        continue

    # Get ID counter for the year.
    if regress_result.timestamp:
      id_year = regress_result.timestamp.year
    else:
      id_year = None

    counter = counters.get(id_year)
    if not counter:
      counter = _get_counter(id_year)
      counters[id_year] = counter

    try:
      cur_id = 'OSV-{}-{}'.format(counter.key.id(), counter.next_id)
      logging.info('Allocating %s.', cur_id)
      counter.next_id += 1

      # Create the Bug now to avoid races when this cron is run again before the
      # impact task finishes.
      bug = osv.Bug(
          db_id=cur_id,
          timestamp=datetime.datetime.utcnow(),
          public=False,
          source_id=key_id,
          status=osv.BugStatus.UNPROCESSED)
      bug.put()

      logging.info('Requesting impact for %s.', key_id)
      publisher.publish(
          _TASKS_TOPIC,
          data=b'',
          type='impact',
          source_id=key_id,
          allocated_id=cur_id)
    finally:
      counter.put()

  return 0


if __name__ == '__main__':
  sys.exit(main())
