# Copyright 2021 Google LLC
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
"""OSV cron handlers."""

import datetime
import json
import logging

from flask import abort
from flask import Blueprint
from flask import request
from google.cloud.datastore_admin_v1.gapic import datastore_admin_client \
    as ds_admin
from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud import secretmanager
import requests

import osv
import monorail

_PROJECT = 'oss-vdb'
_PROJECT_ID = '651737493649'
_BUG_REDO_DAYS = 14
_CRON_ROUTE = '/cron'
_BACKUP_BUCKET = 'osv-backup'

_TASKS_TOPIC = 'projects/{project}/topics/{topic}'.format(
    project=_PROJECT, topic='tasks')

blueprint = Blueprint('handlers', __name__)


def _get_counter(year=None):
  """Get next Bug ID."""
  if year is None:
    year = datetime.datetime.utcnow().year

  key = ndb.Key(osv.IDCounter, year)

  counter = key.get()
  if counter:
    return counter

  return osv.IDCounter(id=year, next_id=1)


def make_affected_commits_public(bug):
  """Make related AffectedCommit entities public."""
  to_update = []

  query = osv.AffectedCommit.query(osv.AffectedCommit.bug_id == bug.key.id())
  for affected_commit in query:
    affected_commit.public = True
    to_update.append(affected_commit)

  if to_update:
    ndb.put_multi(to_update)


def get_monorail_service_account():
  """Get monorail service account credentials."""
  client = secretmanager.SecretManagerServiceClient()
  response = client.access_secret_version(
      f'projects/{_PROJECT_ID}/secrets/monorail-service-account/versions/latest'
  )
  return json.loads(response.payload.data.decode())


@blueprint.route(_CRON_ROUTE + '/make-bugs-public')
def make_bugs_public():
  """Mark bugs public."""
  if not request.headers.get('X-Appengine-Cron'):
    abort(403)

  monorail_account = get_monorail_service_account()
  monorail_client = monorail.Client('oss-fuzz', monorail_account)

  query = osv.Bug.query(
      osv.Bug.public == False,  # pylint: disable=singleton-comparison
      osv.Bug.status == osv.BugStatus.PROCESSED)

  to_mark_public = []
  for bug in query:
    issue_id = bug.issue_id
    if not issue_id:
      logging.info('Missing issue_id for %s.', bug.key.id())
      continue

    try:
      issue = monorail_client.get_issue(issue_id)
    except requests.exceptions.HTTPError:
      logging.error('Failed to get issue %s.', issue_id)
      continue

    labels = [label['label'].lower() for label in issue['labels']]
    if 'restrict-view-commit' not in labels:
      bug.public = True
      logging.info('Marking %s as public.', bug.key.id())
      to_mark_public.append(bug)
      make_affected_commits_public(bug)

  if to_mark_public:
    ndb.put_multi(to_mark_public)

  return 'done'


@blueprint.route(_CRON_ROUTE + '/process-results')
def process_results():
  """Generate impact requests."""
  if not request.headers.get('X-Appengine-Cron'):
    abort(403)

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
      cur_id = '{}-{}'.format(counter.key.id(), counter.next_id)
      logging.info('Allocating OSV-%s.', cur_id)
      counter.next_id += 1

      # Create the Bug now to avoid races when this cron is run again before the
      # impact task finishes.
      bug = osv.Bug(
          id=cur_id,
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

  # Re-compute bugs that aren't fixed.
  for bug in osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                           osv.Bug.fixed == ''):
    publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='impact',
        source_id=bug.source_id,
        allocated_id=bug.key.id())

  # Re-compute existing Bugs for a period of time, as upstream changes may
  # affect results.
  cutoff_time = (
      datetime.datetime.utcnow() - datetime.timedelta(days=_BUG_REDO_DAYS))
  query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                        osv.Bug.timestamp >= cutoff_time)

  for bug in query:
    logging.info('Re-requesting impact for %s.', bug.key.id())
    if not bug.fixed:
      # Previous query already requested impact tasks for unfixed bugs.
      continue

    publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='impact',
        source_id=bug.source_id,
        allocated_id=bug.key.id())

  return 'done'


@blueprint.route(_CRON_ROUTE + '/generate-package-info-tasks')
def generate_package_info_tasks():
  """Generate package_info tasks."""
  if not request.headers.get('X-Appengine-Cron'):
    abort(403)

  publisher = pubsub_v1.PublisherClient()
  query = osv.Bug.query(
      projection=(osv.Bug.project, osv.Bug.ecosystem, osv.Bug.repo_url),
      distinct_on=(osv.Bug.project, osv.Bug.ecosystem))
  for result in query:
    if not result.project or not result.repo_url:
      continue

    if result.ecosystem is None:
      # Invalid/incomplete bug.
      continue

    publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='package_info',
        package_name=result.project,
        ecosystem=result.ecosystem,
        repo_url=result.repo_url)

  return 'done'


@blueprint.route(_CRON_ROUTE + '/backup')
def backup():
  """Create a Datastore backup."""
  if not request.headers.get('X-Appengine-Cron'):
    abort(403)

  client = ds_admin.DatastoreAdminClient()
  client.export_entities(
      project_id=_PROJECT, output_url_prefix=f'gs://{_BACKUP_BUCKET}')

  return 'done'


@blueprint.route('/_ah/warmup')
def warmup():
  """Warmup handler."""
  return 'OK'
