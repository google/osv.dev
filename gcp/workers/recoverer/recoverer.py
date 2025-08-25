#!/usr/bin/env python3
# Copyright 2025 Google LLC
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
"""OSV failed task recoverer."""

import base64
import datetime
import logging
import os
import sys

from google.cloud import ndb
from google.cloud import pubsub_v1

import osv
from osv.logs import setup_gcp_logging

_FAILED_TASKS_SUBSCRIPTION = 'recovery'

_ndb_client = None


def ndb_client():
  """Get the ndb client.
  Lazily initialized to allow testing with datastore emulator."""
  global _ndb_client
  if _ndb_client is None:
    _ndb_client = ndb.Client()
  return _ndb_client


def handle_gcs_retry(message: pubsub_v1.types.PubsubMessage) -> bool:
  """Handle a failed GCS write."""
  try:
    vuln = osv.vulnerability_pb2.Vulnerability.FromString(message.data)
  except Exception:
    logging.error(
        'gcs_retry: failed to decode protobuf. Ignoring message.',
        # chuck the data into the GCP log fields in case it's useful.
        extra={
            'json_fields': {
                'data': base64.encodebytes(message.data).decode()
            }
        })
    return True
  modified = vuln.modified.ToDatetime(datetime.UTC)
  bucket = osv.gcs.get_osv_bucket()
  path = os.path.join(osv.gcs.VULN_PB_PATH, vuln.id + '.pb')
  pb_blob = bucket.get_blob(path)
  # Check that the record hasn't been written/updated in the meantime.
  if pb_blob and pb_blob.custom_time and pb_blob.custom_time >= modified:
    logging.warning(
        'gcs_retry: %s was modified before message was processed: '
        'message: %s, blob: %s', vuln.id, modified, pb_blob.custom_time)
    # TODO(michaelkedar): trigger a reimport of the record.
    return True

  pb_blob = bucket.blob(path)
  pb_blob.custom_time = modified
  try:
    pb_blob.upload_from_string(
        message.data, content_type='application/octet-stream')
    return True
  except Exception:
    logging.exception('gcs_retry: failed to upload %s protobuf to GCS', vuln.id)
    return False


def handle_gcs_missing(message: pubsub_v1.types.PubsubMessage) -> bool:
  """Handle a failed GCS read."""
  vuln_id = message.attributes.get('id')
  if not vuln_id:
    logging.error('gcs_missing: message missing id attribute: %s', message)
    return True
  # Re-put the Bug to regenerate the GCS & Datastore entities
  with ndb_client().context():
    bug = osv.Bug.get_by_id(vuln_id)
    if not bug:
      logging.error('gcs_missing: Bug entity not found for %s', vuln_id)
      # TODO(michaelkedar): What can we do in this case?
      return True
    try:
      bug.put()
      return True
    except Exception:
      logging.exception('gcs_missing: failed to put Bug entity for %s', vuln_id)
      return False
  # TODO(michaelkedar): We will want to stop using the Bug entity eventually.
  # This will need to trigger a reimport of the record from the datasource.


def handle_gcs_gen_mismatch(message: pubsub_v1.types.PubsubMessage) -> bool:
  """Handle a generation mismatch when attempting update a part of a record.
  e.g. If a record was reimported while its aliases were being updated.
  """
  vuln_id = message.attributes.get('id')
  field = message.attributes.get('field')
  if not vuln_id or not field:
    logging.error('gcs_gen_mismatch: message missing id or field attribute: %s',
                  message)
    return True

  with ndb_client().context():
    result = osv.gcs.get_by_id_with_generation(vuln_id)
    if result is None:
      logging.error('gcs_gen_mismatch: vulnerability not in GCS - %s', vuln_id)
      logging.info('trying with gcs_missing')
      return handle_gcs_missing(message)
    vuln_proto, generation = result

    def transaction():
      vuln: osv.Vulnerability = osv.Vulnerability.get_by_id(vuln_id)
      if vuln is None:
        logging.error('vulnerability not in Datastore - %s', vuln_id)
        # TODO(michaelkedar): What to do in this case?
        return
      modified = vuln.modified

      if field == 'aliases':
        alias_group = osv.AliasGroup.query(
            osv.AliasGroup.bug_ids == vuln_id).get()
        if alias_group is None:
          aliases = []
          aliases_modified = datetime.datetime.now(datetime.UTC)
        else:
          aliases = sorted(set(alias_group.bug_ids) - {vuln_id})
          aliases_modified = alias_group.last_modified
        # Only update the modified time if it's actually being modified
        if vuln_proto.aliases != aliases:
          vuln_proto.aliases[:] = aliases
          if aliases_modified > modified:
            modified = aliases_modified
          else:
            modified = datetime.datetime.now(datetime.UTC)

      elif field == 'upstream':
        upstream_group = osv.UpstreamGroup.query(
            osv.UpstreamGroup.db_id == vuln_id).get()
        if upstream_group is None:
          upstream = []
          upstream_modified = datetime.datetime.now(datetime.UTC)
        else:
          upstream = upstream_group.upstream_ids
          upstream_modified = upstream_group.last_modified
        # Only update the modified time if it's actually being modified
        if vuln_proto.upstream != upstream:
          vuln_proto.upstream[:] = upstream
          if upstream_modified > modified:
            modified = upstream_modified
          else:
            modified = datetime.datetime.now(datetime.UTC)

      vuln_proto.modified.FromDatetime(modified)
      osv.ListedVulnerability.from_vulnerability(vuln_proto).put()
      vuln.modified = modified
      vuln.put()

    try:
      ndb.transaction(transaction)
    except Exception:
      logging.exception(
          'gcs_gen_mismatch: Datastore transaction failed for %s %s', vuln_id,
          field)
      return False
    try:
      osv.gcs.upload_vulnerability(vuln_proto, generation)
      return True
    except Exception:
      logging.exception('gcs_gen_mismatch: Writing to bucket failed for %s %s',
                        vuln_id, field)
      return False


def handle_generic(message: pubsub_v1.types.PubsubMessage) -> bool:
  """Generic message handler."""
  task_type = message.attributes.get('type', 'unknown')
  logging.error('`%s` task could not be processed: %s', task_type, message)
  # TODO(michaelkedar): We should store these somewhere.
  return True


HANDLERS = {
    'gcs_retry': handle_gcs_retry,
    'gcs_missing': handle_gcs_missing,
    'gcs_gen_mismatch': handle_gcs_gen_mismatch,
}


def handle_task(message: pubsub_v1.types.PubsubMessage) -> bool:
  """Handle a 'failed-tasks' message."""
  task_type = message.attributes.get('type')
  handler = HANDLERS.get(task_type, handle_generic)
  return handler(message)


def main():
  project = osv.utils.get_google_cloud_project()
  if not project:
    logging.error('GOOGLE_CLOUD_PROJECT not set')
    sys.exit(1)

  with pubsub_v1.SubscriberClient() as subscriber:
    subscription = subscriber.subscription_path(project,
                                                _FAILED_TASKS_SUBSCRIPTION)

    while True:
      response = subscriber.pull(subscription=subscription, max_messages=1)
      if not response.received_messages:
        continue

      message = response.received_messages[0].message
      ack_id = response.received_messages[0].ack_id
      # Try handle the task
      # If successful (returned True), acknowledge it.
      # Otherwise, nack the task to trigger it to be redelivered.
      if handle_task(message):
        subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
      else:
        subscriber.modify_ack_deadline(
            subscription=subscription, ack_ids=[ack_id], ack_deadline_seconds=0)


if __name__ == '__main__':
  setup_gcp_logging('recoverer')
  main()
