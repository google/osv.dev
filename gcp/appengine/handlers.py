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

# TODO(michaelkedar): Cloud Run equivalents need to be made for these.
# This cron logic should probably be removed from the website entirely.
# https://github.com/google/osv.dev/issues/1249

import datetime
import logging

from flask import abort
from flask import Blueprint
from flask import request
from flask import send_file, send_from_directory
from google.cloud.datastore_admin_v1.services.datastore_admin import client \
    as ds_admin
from google.cloud import ndb
from google.cloud import pubsub_v1
import requests

import osv
import monorail

_PROJECT = 'oss-vdb'
_PROJECT_ID = '651737493649'
_BUG_REDO_DAYS = 14
_CRON_ROUTE = '/cron'
_BACKUP_BUCKET = 'osv-backup'
_MONORAIL_ACCOUNT = 'service@oss-vdb.iam.gserviceaccount.com'

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
  """Make related AffectedCommits entities public."""
  query = osv.AffectedCommits.query(osv.AffectedCommits.bug_id == bug.key.id())
  for affected_commits in query:
    affected_commits.public = True
    # Write entities individually as they can be large.
    affected_commits.put()


@blueprint.route(_CRON_ROUTE + '/make-bugs-public')
def make_bugs_public():
  """Mark bugs public."""
  if not request.headers.get('X-Appengine-Cron'):
    abort(403)

  monorail_client = monorail.Client('oss-fuzz', _MONORAIL_ACCOUNT)
  query = osv.Bug.query(osv.Bug.public == False)  # pylint: disable=singleton-comparison

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


# TODO(michaelkedar): Cloud Run is currently using this its health checks.
# Should replace this with the conventional /healthz endpoint.
@blueprint.route('/_ah/warmup')
def warmup():
  """Warmup handler."""
  return 'OK'


@blueprint.route('/public_keys/<path:filename>')
def public_keys(filename):
  """Public keys handler."""
  return send_from_directory(
      'dist/public_keys', filename, mimetype='text/plain')


@blueprint.route('/docs/osv_service_v1.swagger.json')
def swagger():
  """Swagger file handler."""
  return send_file('docs/osv_service_v1.swagger.json')
