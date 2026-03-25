#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
"""Cron job to generate Vanir signatures for modified vulnerabilities."""

import argparse
import json
import logging
import os
import time

from google.cloud import ndb
from google.protobuf import json_format

import osv
import osv.logs
import osv.models
import osv.gcs
from osv import vulnerability_pb2

from vanir import vulnerability_manager

JOB_NAME = 'vanir_signatures'
JOB_DATA_LAST_RUN = 'vanir_signatures_last_run'


def _generate_vanir_signatures(
    vulnerability: vulnerability_pb2.Vulnerability
) -> vulnerability_pb2.Vulnerability:
  """Generates Vanir signatures for a vulnerability."""
  logging.info('Generating Vanir signatures for %s', vulnerability.id)
  try:
    vuln_manager = vulnerability_manager.generate_from_json_string(
        content=json.dumps([
            json_format.MessageToDict(
                vulnerability, preserving_proto_field_name=True)
        ]),)
    vuln_manager.generate_signatures()

    if not vuln_manager.vulnerabilities:
      logging.warning('Vanir signature generation resulted in no '
                      'vulnerabilities.')
      return vulnerability

    return vuln_manager.vulnerabilities[0].to_proto()
  except Exception:
    logging.exception('Failed to generate Vanir signatures for %s',
                      vulnerability.id)
    return vulnerability


def affected_is_kernel(affected: vulnerability_pb2.Affected) -> bool:
  """Returns True if the affected package is a Linux kernel."""
  if affected.package.name == 'Kernel' and \
     affected.package.ecosystem == 'Linux':
    return True

  if any('git.kernel.org/pub/scm/linux/kernel/git' in ar.repo
         for ar in affected.ranges):
    return True

  return False


def process_vulnerability(vuln_id, dry_run=False, output_dir=None):
  """Process a single vulnerability to generate Vanir signatures."""
  logging.debug('Processing %s', vuln_id)

  vuln_and_gen = osv.gcs.get_by_id_with_generation(vuln_id)
  if not vuln_and_gen:
    logging.warning('Vulnerability %s not found in GCS', vuln_id)
    return False

  vulnerability, gcs_gen = vuln_and_gen
  original_vulnerability = vulnerability_pb2.Vulnerability()
  original_vulnerability.CopyFrom(vulnerability)

  if not any(r.type == vulnerability_pb2.Range.GIT
             for affected in vulnerability.affected
             for r in affected.ranges):
    logging.debug(
        'Skipping Vanir signature generation for %s as it has no '
        'GIT affected ranges.', vuln_id)
    return False

  if any('vanir_signatures' in affected.database_specific.fields
         for affected in vulnerability.affected):
    logging.debug(
        'Skipping Vanir signature generation for %s as it already has '
        'Vanir signatures.', vuln_id)
    return False

  if any(affected_is_kernel(affected) for affected in vulnerability.affected):
    logging.debug('Skipping %s as it is a Kernel vulnerability', vuln_id)
    return False

  enriched_vulnerability = _generate_vanir_signatures(vulnerability)

  if original_vulnerability == enriched_vulnerability:
    logging.debug('No changes in Vanir signatures for %s', vuln_id)
    return False

  if dry_run:
    logging.info('Dry run: would have updated %s', vuln_id)
    if output_dir:
      if not os.path.exists(output_dir):
        os.makedirs(output_dir)
      output_path = os.path.join(output_dir, f'{vuln_id}.json')
      with open(output_path, 'w') as f:
        f.write(
            json_format.MessageToJson(
                enriched_vulnerability, preserving_proto_field_name=True))
      logging.info('Saved enriched vulnerability to %s', output_path)
    return True

  bug = osv.Bug.get_by_id(vuln_id)
  if not bug:
    logging.error('Bug %s not found in Datastore', vuln_id)
    return False

  bug.update_from_vulnerability(enriched_vulnerability)
  bug.last_modified = osv.utcnow()
  bug.put()

  logging.info('Updated Datastore for %s, now uploading to GCS', vuln_id)
  try:
    osv.gcs.upload_vulnerability(enriched_vulnerability, gcs_gen)
  except Exception:
    logging.error('Failed to upload %s to GCS', vuln_id)
    # Even if GCS upload fails, we return True as the Datastore is updated.
    # Bug._post_put_hook will also attempt to upload the vulnerability.

  return True


def main():
  """Main entry point for the cron job."""
  parser = argparse.ArgumentParser(description='Vanir signatures cron job.')
  parser.add_argument(
      '--dry-run', action='store_true', help='Perform a dry run.')
  parser.add_argument(
      '--output-dir',
      help='Directory to save enriched vulnerabilities during dry run.')
  args = parser.parse_args()

  if args.dry_run:
    logging.getLogger().setLevel(logging.DEBUG)

  last_run_key = ndb.Key(osv.models.JobData, JOB_DATA_LAST_RUN)
  last_run_data = last_run_key.get()

  # Capture current time to use as last_run for the next time.
  current_run = osv.utcnow()

  if last_run_data:
    last_run = last_run_data.value
    logging.info('Running Vanir signature generation since %s', last_run)
    query = osv.models.Vulnerability.query(
        osv.models.Vulnerability.modified > last_run)
  else:
    logging.info('No last run found, querying all vulnerabilities.')
    query = osv.models.Vulnerability.query()

  vuln_ids = [key.id() for key in query.fetch(keys_only=True)]

  logging.info('Found %d vulnerabilities to process', len(vuln_ids))

  generated_count = 0
  start_time = time.time()
  for vuln_id in vuln_ids:
    try:
      if process_vulnerability(vuln_id, args.dry_run, args.output_dir):
        generated_count += 1
    except Exception:
      logging.exception('Error processing vulnerability %s', vuln_id)
  end_time = time.time()

  total_time = end_time - start_time
  avg_time = total_time / len(vuln_ids) if vuln_ids else 0
  logging.info('Processed %d vulnerabilities, generated %d new signatures.',
               len(vuln_ids), generated_count)
  logging.info('Total processing time: %.2f seconds (Avg %.4f seconds/vuln)',
               total_time, avg_time)

  if args.dry_run:
    logging.info('Dry run: would have updated last_run to %s', current_run)
    return

  # Update last_run timestamp
  if not last_run_data:
    last_run_data = osv.models.JobData(id=JOB_DATA_LAST_RUN)

  last_run_data.value = current_run
  last_run_data.put()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging(JOB_NAME)
  with _ndb_client.context():
    main()
