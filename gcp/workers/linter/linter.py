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
"""Run osv-linter on all OSV records."""

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Any
import zipfile

from google.cloud import ndb, storage

import osv.logs
from osv.models import utcnow

# The Go binary is copied to /usr/local/bin in the Dockerfile
OSV_LINTER = 'osv-linter'
VULN_BUCKET = 'osv-test-vulnerabilities'
ZIP_FILE_PATH = 'all.zip'
TEST_DATA = '/linter/test_data'
GCP_PROJECT = 'oss-vdb-test'

LINTER_EXPORT_BUCKET = 'osv-test-public-import-logs'
LINTER_RESULT_DIR = 'linter-result'

ERROR_CODE_MAPPING = {
    'SCH:001': osv.ImportFindings.INVALID_JSON,
    'REC:001': osv.ImportFindings.INVALID_RECORD,
    'REC:002': osv.ImportFindings.INVALID_ALIASES,
    'REC:003': osv.ImportFindings.INVALID_UPSTREAM,
    'REC:004': osv.ImportFindings.INVALID_RELATED,
    'RNG:001': osv.ImportFindings.INVALID_RANGE,
    'RNG:002': osv.ImportFindings.INVALID_RANGE,
    'PKG:001': osv.ImportFindings.INVALID_PACKAGE,
    'PKG:002': osv.ImportFindings.INVALID_VERSION,
    'PKG:003': osv.ImportFindings.INVALID_PURL,
}


def construct_prefix_to_source_map() -> dict[str, str]:
  """construct the prefix to source name map from source repository db"""
  prefix_to_source = {}
  try:
    sources = osv.SourceRepository.query().fetch()
    for source in sources:
      for prefix in source.db_prefix:
        prefix_to_source[prefix] = source.name
  except Exception as e:
    logging.exception('Failed to query SourceRepository: %s', e)
    sys.exit(1)

  return prefix_to_source


def download_file(source: str, destination: str):
  """Downloads the required file from bucket."""
  storage_client = storage.Client()
  bucket = storage_client.get_bucket(VULN_BUCKET)
  try:
    blob = bucket.blob(source)
    blob.download_to_filename(destination)
  except Exception as e:
    logging.exception('Failed to download %s: %s', source, e)
    sys.exit(1)
  logging.info('Downloaded to %s.', destination)


def download_osv_data(tmp_dir: str):
  """download osv data from all.zip to a temp directory"""
  logging.info('Starts to download %s from bucket %s.', ZIP_FILE_PATH,
               VULN_BUCKET)
  all_zip = os.path.join(tmp_dir, ZIP_FILE_PATH)
  download_file(ZIP_FILE_PATH, all_zip)
  logging.info('Unzipping %s into %s...', all_zip, tmp_dir)
  with zipfile.ZipFile(all_zip, 'r') as zip_ref:
    zip_ref.extractall(tmp_dir)
  logging.info('Successfully unzipped files to %s.', tmp_dir)


def process_linter_result(output: Any, bugs: set, prefix_to_source: dict[str,
                                                                         str]):
  """process the linter results and update/add findings into db."""
  time = utcnow()
  total_findings = 0

  for filename, findings_list in output.items():
    bug_id = os.path.splitext(os.path.basename(filename))[0]
    bugs.add(bug_id)
    findings_already_added = set()
    if not findings_list:
      continue

    total_findings += len(findings_list)
    for finding in findings_list:
      code = finding.get('Code', 'UNKNOWN_CODE')
      import_finding_code = ERROR_CODE_MAPPING.get(code,
                                                   osv.ImportFindings.NONE)

      # Only adds the same finding code once per bug using set().
      findings_already_added.add(import_finding_code)

    sorted_findings = sorted(list(findings_already_added))
    prefix = bug_id.split('-')[0] + '-'
    source = prefix_to_source.get(prefix, '')
    record_quality_finding(bug_id, source, sorted_findings, time)

  if total_findings > 0:
    logging.info('OSV Linter found %d issues across files.', total_findings)


def record_quality_finding(bug_id: str, source: str,
                           new_findings: list[osv.ImportFindings],
                           findingtimenow: datetime):
  """Record or update the linter finding about a record in Datastore."""
  existing_finding = osv.ImportFinding.get_by_id(bug_id)

  if existing_finding:
    if new_findings != existing_finding.findings:
      existing_finding.findings = new_findings
      existing_finding.last_attempt = findingtimenow
      existing_finding.put()
      logging.debug('DB Update for %s: Set findings to %s. Source: %s', bug_id,
                    new_findings, source)
  elif new_findings:
    osv.ImportFinding(
        bug_id=bug_id,
        source=source,
        findings=new_findings,
        first_seen=findingtimenow,
        last_attempt=findingtimenow).put()
    logging.debug('DB Create for %s: Set findings to %s. Source: %s', bug_id,
                  new_findings, source)


def upload_record_to_bucket(json_result: Any, prefix_to_source: dict[str, str]):
  """Uploads the linter result to a GCS bucket, creating one file per source."""
  storage_client = storage.Client()
  bucket = storage_client.get_bucket(LINTER_EXPORT_BUCKET)

  # Delete existing results first.
  logging.info('Deleting existing linter results from %s/%s.',
               LINTER_EXPORT_BUCKET, LINTER_RESULT_DIR)
  blobs_to_delete = list(bucket.list_blobs(prefix=LINTER_RESULT_DIR))
  if blobs_to_delete:
    for blob in blobs_to_delete:
      blob.delete()
    logging.info('Finished deleting %d existing linter results.',
                 len(blobs_to_delete))
  else:
    logging.info('No existing linter results to delete.')

  source_results = {}
  for filename, findings in json_result.items():
    bug_id = os.path.splitext(os.path.basename(filename))[0]
    prefix = bug_id.split('-')[0] + '-'
    source = prefix_to_source.get(prefix, '')

    if source not in source_results:
      source_results[source] = {}
    source_results[source][filename] = findings

  logging.info('Uploading linter results for %d sources.', len(source_results))
  for source, results in source_results.items():
    if not results:
      continue

    target_path = os.path.join(LINTER_RESULT_DIR, source, 'result.json')
    logging.info('Uploading linter result for source '
                 '%s'
                 ' to %s/%s', source, LINTER_EXPORT_BUCKET, target_path)

    blob = bucket.blob(target_path)
    blob.upload_from_string(
        json.dumps(results, indent=2), content_type='application/json')
    logging.info("Successfully uploaded linter result for source '%s'.", source)


def parse_and_record_linter_output(json_output_str: str,
                                   prefix_to_source: dict[str, str]):
  """
  Parses the JSON output from the OSV linter and records findings.
  Manages create, update, and delete findings in the Datastore.
  """
  try:
    linter_output_json = json.loads(json_output_str)
    logging.info('Successfully parsed OSV Linter JSON output.')
  except Exception as e:
    logging.error('Failed to parse OSV Linter JSON output: %s', e)
    return

  # Upload linter result to GCS bucket
  upload_record_to_bucket(linter_output_json, prefix_to_source)

  # Fetch all existing ids from importfindings db
  all_finding_keys = osv.ImportFinding.query().fetch(keys_only=True)
  existing_db_bug_ids = set(key.id() for key in all_finding_keys)
  logging.info('Fetched %d existing findings from the database.',
               len(existing_db_bug_ids))

  if not linter_output_json:
    logging.info('OSV Linter output was empty JSON, indicating no findings.')
    return

  linter_bugs = set()

  # Process linter results
  process_linter_result(linter_output_json, linter_bugs, prefix_to_source)

  # Delete entries from db that are no longer found by the linter
  ids_to_delete = existing_db_bug_ids - linter_bugs
  if ids_to_delete:
    logging.info('Found %d stale entries to delete from DB: %s',
                 len(ids_to_delete), ids_to_delete)
    deleted_count = 0
    for id_to_delete in ids_to_delete:
      entity_to_delete = osv.ImportFinding.get_by_id(id_to_delete)
      entity_to_delete.key.delete()
      logging.debug('Deleted stale entry for %s.', id_to_delete)
      deleted_count += 1
    logging.info('Successfully deleted %d stale entries.', deleted_count)


def main():
  """Run linter"""
  prefix_to_source = construct_prefix_to_source_map()

  parser = argparse.ArgumentParser(description='Linter')
  parser.add_argument('--work_dir', help='Working directory', default=TEST_DATA)
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)

  with tempfile.TemporaryDirectory(dir=tmp_dir) as tmp_dir:
    download_osv_data(tmp_dir)
    try:
      command = [
          OSV_LINTER, 'record', 'check', '--json', '--collection', 'offline',
          tmp_dir
      ]
      logging.info('Executing Go linter: %s', ' '.join(command))

      result = subprocess.run(
          command, capture_output=True, text=True, check=False, timeout=2000)

      parse_and_record_linter_output(result.stdout, prefix_to_source)

    except Exception as e:
      logging.error('An unexpected error occurred: %e', e)
      sys.exit(1)


if __name__ == '__main__':
  osv.logs.setup_gcp_logging('linter')

  _ndb_client = ndb.Client()
  with _ndb_client.context():
    main()
