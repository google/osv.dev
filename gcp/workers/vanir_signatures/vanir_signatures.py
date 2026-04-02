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
import datetime
import json
import logging
from concurrent import futures

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
JOB_DATA_RETRY_LIST = 'vanir_signatures_retry_list'


def _generate_vanir_signatures_batch(
    vulnerabilities: list[vulnerability_pb2.Vulnerability]
) -> dict[str, list[vulnerability_pb2.Vulnerability]]:
  """Generates Vanir signatures for a batch of vulnerabilities."""
  if not vulnerabilities:
    return {}

  logging.info('Generating Vanir signatures for batch of %d',
               len(vulnerabilities))

  try:
    vuln_dicts = [
        json_format.MessageToDict(v, preserving_proto_field_name=True)
        for v in vulnerabilities
    ]
    vuln_manager = vulnerability_manager.generate_from_json_string(
        content=json.dumps(vuln_dicts))
    vuln_manager.generate_signatures()

    if not vuln_manager.vulnerabilities:
      logging.warning('Vanir signature generation resulted in no '
                      'vulnerabilities.')
      return {v.id: [v] for v in vulnerabilities}

    results = {}
    for v in vuln_manager.vulnerabilities:
      proto = v.to_proto()
      if proto.id not in results:
        results[proto.id] = []
      results[proto.id].append(proto)

    # Ensure all input IDs are in results, even if they weren't enriched
    for v in vulnerabilities:
      if v.id not in results:
        results[v.id] = [v]

    return results

  except Exception:
    logging.exception('Failed to generate Vanir signatures for batch of %d',
                      len(vulnerabilities))
    return {v.id: [v] for v in vulnerabilities}


def affected_is_kernel(affected: vulnerability_pb2.Affected) -> bool:
  """Returns True if the affected package is a Linux kernel."""
  if (affected.package.name == 'Kernel' and
      affected.package.ecosystem == 'Linux'):
    return True

  if any('git.kernel.org/pub/scm/linux/kernel/git' in ar.repo
         for ar in affected.ranges):
    return True

  return False


def has_vanir_signatures(
    vulnerability: vulnerability_pb2.Vulnerability) -> bool:
  """Returns True if any affected entry has a vanir_signatures."""
  for affected in vulnerability.affected:
    if (affected.HasField('database_specific') and
        'vanir_signatures' in affected.database_specific):
      return True
  return False


def process_batch(vuln_ids: list[str],
                  dry_run: bool = False,
                  max_workers: int = 10) -> tuple[int, list[str]]:
  """Process a batch of vulnerabilities."""
  if not vuln_ids:
    return 0, []

  logging.info('Processing batch of %d vulnerabilities', len(vuln_ids))

  # Parallel fetch OSV records from GCS
  vulnerabilities_to_process = []
  gcs_generations = {}

  with futures.ThreadPoolExecutor(max_workers=max_workers) as executor:

    results = list(executor.map(osv.gcs.get_by_id_with_generation, vuln_ids))

    for i, res in enumerate(results):
      vuln_id = vuln_ids[i]
      if not res:
        logging.warning('Vulnerability %s not found in GCS', vuln_id)
        continue

      vulnerability, gcs_gen = res

      # Filter
      if not any(r.type == vulnerability_pb2.Range.GIT
                 for affected in vulnerability.affected
                 for r in affected.ranges):
        logging.debug('Skipping %s: no GIT affected ranges.', vuln_id)
        continue

      if any(
          affected_is_kernel(affected) for affected in vulnerability.affected):
        logging.debug('Skipping %s: it is a Kernel vulnerability', vuln_id)
        continue

      if vulnerability.HasField('withdrawn'):
        logging.debug('Skipping %s: it is withdrawn', vuln_id)
        continue

      # This is for the initial run otherwise it will take too long time for
      # all vulnerabilities
      if has_vanir_signatures(vulnerability):
        logging.debug('Skipping %s: already has Vanir signatures', vuln_id)
        continue

      vulnerabilities_to_process.append(vulnerability)
      gcs_generations[vulnerability.id] = gcs_gen

  if not vulnerabilities_to_process:
    return 0, []

  # Batch signature generation
  batch_results = _generate_vanir_signatures_batch(vulnerabilities_to_process)

  # Collect all vulnerabilities to update in GCS/Datastore.
  all_enriched = []
  for original_vuln in vulnerabilities_to_process:
    enriched = batch_results.get(original_vuln.id, [original_vuln])
    for v in enriched:
      if v != original_vuln:
        all_enriched.append(v)

  if not all_enriched:
    return 0, []

  if dry_run:
    for enriched_vuln in all_enriched:
      logging.info('Dry run: would have updated %s', enriched_vuln.id)
    return len(all_enriched), []

  # Update Datastore and GCS
  updated_count = 0
  failed_ids = []

  # Batch fetch Vulnerabilities from Datastore
  vuln_keys = [ndb.Key(osv.models.Vulnerability, v.id) for v in all_enriched]
  vulns = ndb.get_multi(vuln_keys)

  for v, vuln in zip(all_enriched, vulns):
    if not vuln:
      logging.error('Vulnerability %s not found in Datastore', v.id)
      continue

    # Capture current time, but only apply to proto now.
    # We will only apply to Datastore entity and put() on successful GCS upload.
    now = osv.utcnow()
    v.modified.FromDatetime(now)
    now_iso = now.strftime('%Y-%m-%dT%H:%M:%SZ')

    for affected in v.affected:
      if (affected.HasField('database_specific') and
          'vanir_signatures' in affected.database_specific):
        affected.database_specific['vanir_signatures_modified'] = now_iso

    # Use gcs_generations[original_id] ONLY if it matches enriched ID.
    gen = gcs_generations.get(v.id)
    try:
      osv.gcs.upload_vulnerability(v, gen)
      updated_count += 1
    except Exception:
      logging.exception('Failed upload for %s. Adding to retry list.', v.id)
      failed_ids.append(v.id)
      continue

    # On successful upload, update Datastore entity.
    vuln.modified = now
    vuln.put()

  return updated_count, failed_ids


def main():
  """Main entry point for the cron job."""
  parser = argparse.ArgumentParser(description='Vanir signatures cron job.')
  parser.add_argument(
      '--batch-size',
      type=int,
      default=500,
      help='Number of vulnerabilities to process in each batch.')
  parser.add_argument(
      '--max-workers',
      type=int,
      default=10,
      help=('Maximum number of parallel workers. Note that total threads '
            'spawned will be max_workers * max_workers (default 100).'))
  parser.add_argument(
      '--dry-run', action='store_true', help='Perform a dry run.')
  parser.add_argument(
      '--hours',
      type=int,
      help='Number of hours back to process modified records.')
  args = parser.parse_args()

  if args.dry_run:
    logging.getLogger().setLevel(logging.DEBUG)

  last_run_key = ndb.Key(osv.models.JobData, JOB_DATA_LAST_RUN)
  last_run_data = last_run_key.get()

  retry_list_key = ndb.Key(osv.models.JobData, JOB_DATA_RETRY_LIST)
  retry_list_data = retry_list_key.get()

  # Capture current time to use as last_run for the next time.
  current_run = osv.utcnow()

  if args.hours:
    last_run = current_run - datetime.timedelta(hours=args.hours)
    logging.info(
        'Running Vanir signature generation for the last %d hours (since %s)',
        args.hours, last_run)
  else:
    last_run = last_run_data.value if last_run_data else None
    if last_run:
      logging.info('Running Vanir signature generation since last run: %s',
                   last_run)
    else:
      logging.info('No last run found, querying all vulnerabilities.')

  # Single global query for modified vulnerabilities
  query = osv.models.Vulnerability.query()
  if last_run:
    query = query.filter(osv.models.Vulnerability.modified > last_run)

  total_generated_count = 0
  total_processed_count = 0
  all_failed_ids = []

  # Note that total threads spawned will be max_workers * max_workers (one pool
  # for batches, one pool within each batch for GCS fetches).
  with futures.ThreadPoolExecutor(max_workers=args.max_workers) as executor:

    def process_with_context(batch):
      with ndb.Client().context():
        return process_batch(batch, args.dry_run, args.max_workers)

    future_to_batch = {}
    current_batch = []

    logging.info('Streaming vulnerabilities for processing.')
    for key in query.iter(keys_only=True):
      current_batch.append(key.id())
      if len(current_batch) >= args.batch_size:
        f = executor.submit(process_with_context, current_batch)
        future_to_batch[f] = current_batch
        current_batch = []

    # Also add IDs from the retry list
    if retry_list_data and retry_list_data.value:
      retry_ids = list(set(retry_list_data.value))
      logging.info('Adding %d IDs from retry list.', len(retry_ids))
      for i in range(0, len(retry_ids), args.batch_size):
        batch = retry_ids[i:i + args.batch_size]
        f = executor.submit(process_with_context, batch)
        future_to_batch[f] = batch

    if current_batch:
      f = executor.submit(process_with_context, current_batch)
      future_to_batch[f] = current_batch

    if not future_to_batch:
      logging.info('No modified vulnerabilities found.')
    else:
      logging.info('Processing %d batches of vulnerabilities.',
                   len(future_to_batch))
      for future in futures.as_completed(future_to_batch):
        try:
          generated, failed_ids = future.result()
          total_generated_count += generated
          all_failed_ids.extend(failed_ids)
          total_processed_count += len(future_to_batch[future])
        except Exception:
          logging.exception('Failed to process a batch of vulnerabilities')

  logging.info('Processed %d vulnerabilities, generated %d new signatures.',
               total_processed_count, total_generated_count)

  if args.dry_run:
    logging.info('Dry run: would have updated last_run to %s', current_run)
    if all_failed_ids:
      logging.info('Dry run: would have saved %d failed IDs to retry list.',
                   len(set(all_failed_ids)))
    return

  # Update last_run timestamp
  if not last_run_data:
    last_run_data = osv.models.JobData(id=JOB_DATA_LAST_RUN)

  last_run_data.value = current_run
  last_run_data.put()

  # Update retry list
  if not retry_list_data:
    retry_list_data = osv.models.JobData(id=JOB_DATA_RETRY_LIST)

  retry_list_data.value = list(set(all_failed_ids))
  retry_list_data.put()
  if retry_list_data.value:
    logging.info('Saved %d failed IDs to retry list.',
                 len(retry_list_data.value))


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging(JOB_NAME)
  with _ndb_client.context():
    main()
