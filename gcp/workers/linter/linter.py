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
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import subprocess
import sys
import tempfile
import zipfile
from typing import Any, Dict, List, Set, Optional # Added Optional, Set, Dict, List

from google.cloud import ndb, storage
from google.cloud.storage.bucket import Bucket # For type hint
from google.cloud.storage.blob import Blob # For type hint


import osv.logs # osv.logs.setup_gcp_logging
import osv.models # For osv.models.ImportFindings, osv.models.ImportFinding
from osv.models import utcnow # Direct import for utcnow

# The Go binary is copied to /usr/local/bin in the Dockerfile
OSV_LINTER: str = 'osv-linter'
VULN_BUCKET: str = 'osv-test-vulnerabilities' # Should this be configurable?
ZIP_FILE_PATH: str = 'all.zip'
TEST_DATA: str = '/linter/test_data' # Used as default work_dir
GCP_PROJECT: str = 'oss-vdb-test' # Should this be configurable or env var?

# Mapping from linter error codes to NDB ImportFindings enum members
ERROR_CODE_MAPPING: Dict[str, osv.models.ImportFindings] = {
    'REC:001': osv.models.ImportFindings.INVALID_RECORD,
    'REC:002': osv.models.ImportFindings.INVALID_ALIASES,
    'REC:003': osv.models.ImportFindings.INVALID_UPSTREAM,
    'REC:004': osv.models.ImportFindings.INVALID_RELATED,
    'RNG:001': osv.models.ImportFindings.INVALID_RANGE,
    'RNG:002': osv.models.ImportFindings.INVALID_RANGE, # Duplicate value, but okay for dict
    'PKG:001': osv.models.ImportFindings.INVALID_PACKAGE,
    'PKG:002': osv.models.ImportFindings.INVALID_VERSION,
    'PKG:003': osv.models.ImportFindings.INVALID_PURL,
}

# TODO(gongh@): query the mapping from the SourceRepository database
# instead of hardcoding it.
PREFIX_TO_SOURCE: Dict[str, str] = {
    'ALBA-': 'almalinux-alba',
    'ALEA-': 'almalinux-alea',
    'ALSA-': 'almalinux-alsa',
    'A-': 'android', # Multiple prefixes can map to the same source
    'ASB-': 'android',
    'PUB-': 'android',
    'BIT-': 'bitnami',
    'CGA-': 'chainguard',
    'CURL-': 'curl',
    'CVE-': 'cve-osv',
    'DLA-': 'debian-dla',
    'DSA-': 'debian-dsa',
    'DTSA-': 'debian-dtsa',
    'GHSA-': 'ghsa',
    'GO-': 'go',
    'HSEC-': 'haskell',
    'MGASA-': 'mageia',
    'MAL-': 'malicious-packages',
    'MINI-': 'minimos',
    'OSV-': 'test-oss-fuzz', # This seems specific, maybe should be 'oss-fuzz' or dynamic
    'PSF-': 'psf',
    'PYSEC-': 'python',
    'RSEC-': 'r',
    'RHBA-': 'redhat',
    'RHEA-': 'redhat',
    'RHSA-': 'redhat',
    'RLSA-': 'rockylinux',
    'RXSA-': 'rockylinux-rxsa',
    'RUSTSEC-': 'rust',
    'openSUSE-': 'suse',
    'SUSE-': 'suse',
    'UBUNTU-': 'ubuntu-cve',
    'LSN-': 'ubuntu-lsn',
    'USN-': 'ubuntu-usn',
    'GSD-': 'uvi',
    'V8-': 'V8',
}

# Global NDB client
_ndb_client: ndb.Client


def download_file(source_blob_name: str, destination_file_path: str) -> None: # Renamed args
  """Downloads the required file from VULN_BUCKET."""
  storage_client = storage.Client()
  bucket: Bucket = storage_client.get_bucket(VULN_BUCKET)
  try:
    blob: Blob = bucket.blob(source_blob_name)
    blob.download_to_filename(destination_file_path)
  except Exception as e: # Catch more specific exceptions if possible (e.g., google.cloud.exceptions.NotFound)
    logging.exception('Failed to download %s from bucket %s to %s: %s',
                      source_blob_name, VULN_BUCKET, destination_file_path, e)
    sys.exit(1) # Exit if essential download fails
  logging.info('Downloaded gs://%s/%s to %s.', VULN_BUCKET, source_blob_name, destination_file_path)


def download_osv_data(tmp_dir_path: str) -> None: # Renamed tmp_dir
  """Download OSV data from all.zip in VULN_BUCKET to a temp directory and extract."""
  logging.info('Starting download of %s from bucket %s.', ZIP_FILE_PATH, VULN_BUCKET)
  local_zip_path = os.path.join(tmp_dir_path, ZIP_FILE_PATH) # Renamed all_zip
  download_file(ZIP_FILE_PATH, local_zip_path)

  logging.info('Unzipping %s into %s...', local_zip_path, tmp_dir_path)
  try:
    with zipfile.ZipFile(local_zip_path, 'r') as zip_ref:
      zip_ref.extractall(tmp_dir_path)
    logging.info('Successfully unzipped files to %s.', tmp_dir_path)
  except zipfile.BadZipFile as e:
    logging.exception("Failed to unzip %s: %s", local_zip_path, e)
    sys.exit(1) # Exit if zip file is bad, as no data can be processed


def process_linter_result(
    linter_output: Dict[str, List[Dict[str, Any]]], # Renamed output
    bugs_found_by_linter: Set[str] # Renamed bugs, for collecting IDs found by linter
) -> None:
  """Process the linter results and update/add findings into NDB."""
  current_time: datetime.datetime = utcnow() # Renamed time
  total_findings_count: int = 0 # Renamed total_findings

  for file_path_key, findings_for_file in linter_output.items(): # Renamed filename, findings_list
    # Assuming filename in linter output is relative path or just basename.
    # OSV IDs are typically filename without extension.
    bug_id_str: str = os.path.splitext(os.path.basename(file_path_key))[0] # Renamed bug_id
    bugs_found_by_linter.add(bug_id_str)

    # Collect unique finding codes for this bug_id
    unique_import_findings_for_bug: Set[osv.models.ImportFindings] = set() # Renamed
    if not findings_for_file: # Empty list means no findings for this file
      # This implies we should potentially clear existing findings if any.
      # This is handled by parse_and_record_linter_output's deletion logic.
      # Here, we just note no new findings from linter for this file.
      pass # Continue to next file

    total_findings_count += len(findings_for_file)
    for finding_item in findings_for_file: # Renamed finding
      error_code_str: str = finding_item.get('Code', 'UNKNOWN_CODE') # Renamed code
      # Map linter error code to NDB ImportFindings enum member
      import_finding_enum: osv.models.ImportFindings = ERROR_CODE_MAPPING.get(
          error_code_str, osv.models.ImportFindings.NONE) # Default to NONE if code unknown

      if import_finding_enum != osv.models.ImportFindings.NONE:
        unique_import_findings_for_bug.add(import_finding_enum)

    # Sort findings for consistent storage and comparison
    sorted_unique_findings: List[osv.models.ImportFindings] = sorted(
        list(unique_import_findings_for_bug), key=lambda x: x.value) # Sort by enum value

    # Determine source based on bug ID prefix
    # Ensure bug_id_str is not empty before split
    id_prefix: str = (bug_id_str.split('-', 1)[0] + '-') if '-' in bug_id_str else bug_id_str
    source_name: str = PREFIX_TO_SOURCE.get(id_prefix, '') # Renamed source

    record_quality_finding(bug_id_str, source_name, sorted_unique_findings, current_time)

  if total_findings_count > 0:
    logging.info('OSV Linter reported %d findings across processed files.', total_findings_count)


def record_quality_finding(bug_id: str, source_name: str, # Renamed source
                           new_findings_list: List[osv.models.ImportFindings], # Renamed new_findings
                           finding_time: datetime.datetime # Renamed findingtimenow
                          ) -> None:
  """Record or update the linter finding about a record in Datastore."""
  # osv.models.ImportFinding needed
  existing_finding_model: Optional[osv.models.ImportFinding] = osv.models.ImportFinding.get_by_id(bug_id) # Renamed

  if existing_finding_model:
    # Ensure existing_finding_model.findings is a list for comparison
    current_db_findings = existing_finding_model.findings or []
    if new_findings_list != current_db_findings: # Only update if findings changed
      existing_finding_model.findings = new_findings_list
      existing_finding_model.last_attempt = finding_time
      existing_finding_model.put()
      logging.debug('DB Update for %s: Set findings to %s. Source: %s',
                    bug_id, new_findings_list, source_name)
  elif new_findings_list: # Only create if there are new findings to record
    new_finding_entry = osv.models.ImportFinding( # Renamed
        id=bug_id, # Set NDB key ID
        bug_id=bug_id, # Also store as property
        source=source_name,
        findings=new_findings_list,
        first_seen=finding_time,
        last_attempt=finding_time)
    new_finding_entry.put()
    logging.debug('DB Create for %s: Set findings to %s. Source: %s',
                  bug_id, new_findings_list, source_name)


def parse_and_record_linter_output(json_output_str: str) -> None:
  """
  Parses the JSON output from the OSV linter and records findings.
  Manages create, update, and delete findings in the Datastore.
  """
  linter_output_data: Dict[str, List[Dict[str, Any]]] # Renamed
  try:
    linter_output_data = json.loads(json_output_str)
    logging.info('Successfully parsed OSV Linter JSON output.')
  except json.JSONDecodeError as e: # More specific exception
    logging.error('Failed to parse OSV Linter JSON output: %s', e)
    return # Cannot proceed if output is not valid JSON

  # Fetch all existing ImportFinding keys from NDB to determine stale entries
  # osv.models.ImportFinding needed
  all_finding_keys_query: ndb.Query = osv.models.ImportFinding.query() # Renamed
  all_db_finding_keys: List[ndb.Key] = all_finding_keys_query.fetch(keys_only=True) # Renamed
  # Ensure key.id() is not None before adding to set
  existing_db_bug_ids_set: Set[str] = {key.id() for key in all_db_finding_keys if key and key.id()} # Renamed

  logging.info('Fetched %d existing finding keys from the database.',
               len(existing_db_bug_ids_set))

  if not linter_output_data: # Empty JSON object/dict
    logging.info('OSV Linter output was empty, indicating no findings reported by linter.')
    # If linter output is empty, it means all previously reported issues are now gone.
    # All existing entries in ImportFinding should be considered stale.
    # However, this depends on whether linter outputs empty if no files linted vs. no errors found.
    # Assuming empty means no errors found in any linted file.
    # This implies if a bug_id was previously in ImportFinding but not in this linter run's output keys,
    # it should be cleared/deleted. This is handled by the deletion logic below.
    # If linter_output_data is truly empty (e.g. {}), then linter_bugs_with_findings will be empty.
    # Then ids_to_delete will be all existing_db_bug_ids_set.
    pass


  linter_bugs_with_findings: Set[str] = set() # Renamed linter_bugs

  # Process linter results: updates or creates findings in NDB
  process_linter_result(linter_output_data, linter_bugs_with_findings)

  # Delete entries from NDB for bugs that no longer have linter findings
  # These are bugs that were previously in ImportFinding but NOT in the current linter output.
  ids_to_delete_from_db: Set[str] = existing_db_bug_ids_set - linter_bugs_with_findings # Renamed
  if ids_to_delete_from_db:
    logging.info('Found %d stale finding entries to delete from DB: %s',
                 len(ids_to_delete_from_db), ids_to_delete_from_db)
    deleted_count: int = 0
    keys_to_delete_ndb: List[ndb.Key] = [] # For batch deletion
    for id_val_to_delete in ids_to_delete_from_db: # Renamed id_to_delete
      # osv.models.ImportFinding needed
      # Create key directly for deletion for efficiency
      key_to_delete: ndb.Key = ndb.Key(osv.models.ImportFinding, id_val_to_delete)
      keys_to_delete_ndb.append(key_to_delete)
      logging.debug('Marked stale finding entry for deletion: %s.', id_val_to_delete)

    if keys_to_delete_ndb:
        ndb.delete_multi(keys_to_delete_ndb) # Batch delete
        deleted_count = len(keys_to_delete_ndb)
        logging.info('Successfully deleted %d stale finding entries from DB.', deleted_count)


def main() -> None: # main usually doesn't return a value, or 0 for success / non-0 for error
  """Run linter"""
  parser = argparse.ArgumentParser(description='OSV Linter Runner') # Updated description
  parser.add_argument(
      '--work_dir',
      help='Working directory for temporary data. Defaults to TEST_DATA if not provided.',
      default=TEST_DATA) # Default to TEST_DATA for local runs perhaps
  args = parser.parse_args()

  # Ensure work_dir exists, tmp_dir will be inside it.
  # This tmp_dir is distinct from the one used by tempfile.TemporaryDirectory.
  # It seems like a persistent temp space within work_dir.
  persistent_tmp_dir = os.path.join(args.work_dir, 'tmp_linter_data') # Renamed
  os.makedirs(persistent_tmp_dir, exist_ok=True)

  # Use a managed temporary directory for downloads and extraction that cleans up automatically.
  with tempfile.TemporaryDirectory(dir=persistent_tmp_dir) as temp_extraction_dir: # Renamed
    download_osv_data(temp_extraction_dir)
    try:
      # Command to run the linter binary
      linter_command: List[str] = [ # Renamed command
          OSV_LINTER,
          'record', # Assuming this is a subcommand for the linter
          'check',  # Assuming this is another subcommand
          '--json', # Output in JSON format
          '--collection', 'offline', # Linter specific flags
          temp_extraction_dir # Directory containing the OSV files to lint
      ]
      logging.info('Executing OSV Linter: %s', ' '.join(linter_command))

      # Run the linter subprocess
      # check=False means it won't raise CalledProcessError on non-zero exit.
      # Linter might exit non-zero if findings are present, so check stderr/stdout.
      linter_process_result: subprocess.CompletedProcess[str] = subprocess.run( # Renamed result
          linter_command,
          capture_output=True,
          text=True, # Decodes stdout/stderr as text
          check=False, # Do not raise on non-zero exit code from linter
          timeout=600 # 10 minute timeout for linter run
      )

      if linter_process_result.stderr:
          logging.warning("OSV Linter stderr output:\n%s", linter_process_result.stderr)

      # stdout is expected to be JSON output from the linter
      parse_and_record_linter_output(linter_process_result.stdout)

    except subprocess.TimeoutExpired:
      logging.error('OSV Linter command timed out after %d seconds.', 600)
      sys.exit(1) # Exit with error on timeout
    except Exception as e: # Catch any other unexpected errors during linter execution
      logging.error('An unexpected error occurred while running OSV Linter: %s', e, exc_info=True)
      sys.exit(1)


if __name__ == '__main__':
  osv.logs.setup_gcp_logging('linter') # project_id inferred

  _ndb_client = ndb.Client() # Initialize global NDB client
  with _ndb_client.context(): # Establish NDB context for main execution
    main()
