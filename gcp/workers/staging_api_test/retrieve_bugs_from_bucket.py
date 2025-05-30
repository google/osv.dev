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
"""Fetch Bugs from from export bucket"""

from __future__ import annotations

import logging
import os
import random
import json
import sys
import tempfile
import zipfile
from typing import Any, Dict, List, Optional # Added necessary types

import osv.logs # For osv.logs.setup_gcp_logging

from google.cloud import storage
from google.cloud.storage.bucket import Bucket # For type hint
from google.cloud.storage.blob import Blob # For type hint

GCP_PROJECT: str = 'oss-vdb-test' # Should this be configurable or env var?
BUG_DIR: str = './all_bugs'
VULN_BUCKET: str = 'osv-test-vulnerabilities' # Should this be configurable?
ZIP_FILE_PATH: str = 'all.zip'
ENTRIES_PER_FILE: int = 10000  # amount of bugs per file


def format_bug_for_output(bug: Dict[str, Any]) -> Dict[str, Optional[str]]:
  """Extracts relevant information from a full vulnerability record (dict from JSON).

  This function processes a vulnerability record (as a dictionary) and extracts
  a simplified subset of fields needed for generating API query tests.

  Args:
    bug: A dictionary representing a single vulnerability record.

  Returns:
    A dictionary with simplified bug information: 'db_id', 'project',
    'ecosystem', 'purl', and 'affected_fuzzy' (a chosen version string).
    Returns only 'db_id' if essential 'affected' information is missing.
  """
  # Ensure 'id' field exists, else this function cannot proceed meaningfully.
  bug_id: Optional[str] = bug.get('id')
  if not bug_id:
    # Or raise error, depending on how critical this is.
    # For this script, returning a partial dict might be okay if ID is the minimum.
    # However, the original code would fail later if 'id' is missing for bug['id'].
    # Let's assume 'id' is expected to be present.
    logging.warning("Bug data missing 'id' field: %s", bug)
    # To match original behavior of `bug['id']` potentially failing,
    # we could raise here, or ensure `bug.get('id')` has a fallback if that's desired.
    # For robustness, let's ensure db_id is always a string, even if from a None.
    return {'db_id': str(bug_id) if bug_id else "MISSING_ID"}


  affected_list: Optional[List[Dict[str, Any]]] = bug.get('affected')
  if not affected_list or not isinstance(affected_list, list):
    return {'db_id': str(bug_id)} # Use str(bug_id) for safety

  # Select a random 'affected' entry to get package and version info from.
  # This introduces randomness in which package/version is chosen if multiple exist.
  selected_affected_entry: Dict[str, Any] = random.choice(affected_list) # Renamed affected
  affected_package_info: Optional[Dict[str, Any]] = selected_affected_entry.get('package') # Renamed

  if not affected_package_info or not isinstance(affected_package_info, dict):
    return {'db_id': str(bug_id)}

  # Try to get a version string for querying.
  chosen_version_str: Optional[str] = None # Renamed affected_fuzzy

  # Prefer versions from the 'versions' list if available.
  versions_list: Optional[List[str]] = selected_affected_entry.get('versions')
  if versions_list and isinstance(versions_list, list):
    chosen_version_str = random.choice(versions_list)

  # If no version from 'versions', try to get one from 'ranges' events.
  if not chosen_version_str:
    ranges_list: Optional[List[Dict[str, Any]]] = selected_affected_entry.get('ranges')
    if ranges_list and isinstance(ranges_list, list):
      # Select a random range and then a random event from that range.
      selected_range_item: Dict[str, Any] = random.choice(ranges_list) # Renamed
      events_list: Optional[List[Dict[str, str]]] = selected_range_item.get('events') # Events usually Dict[str,str]
      if events_list and isinstance(events_list, list):
        selected_event: Dict[str, str] = random.choice(events_list) # Renamed
        # Event values ('introduced', 'fixed', etc.) are version strings.
        # Pick a random value from the selected event dict.
        if selected_event and isinstance(selected_event, dict) and selected_event.values():
          chosen_version_str = str(random.choice(list(selected_event.values())))

  return {
      'db_id': str(bug_id), # Ensure db_id is always string
      'project': affected_package_info.get('name'), # Can be None
      'ecosystem': affected_package_info.get('ecosystem'), # Can be None
      'purl': affected_package_info.get('purl'), # Can be None
      'affected_fuzzy': chosen_version_str, # Can be None if no suitable version found
  }


def download_vuln_zip(tmp_dir_path: str) -> None: # Renamed tmp_dir
  """Downloads all.zip file from VULN_BUCKET to tmp_dir_path."""
  # Path to the zip file in GCS
  gcs_zip_file_path = ZIP_FILE_PATH # Assuming ZIP_FILE_PATH is just the name, not full gs:// path
  logging.info('Starting download of gs://%s/%s.', VULN_BUCKET, gcs_zip_file_path)

  storage_client = storage.Client()
  bucket: Bucket = storage_client.get_bucket(VULN_BUCKET)

  try:
    blob: Blob = bucket.blob(gcs_zip_file_path)
    local_destination_path = os.path.join(tmp_dir_path, ZIP_FILE_PATH) # Renamed file_path
    blob.download_to_filename(local_destination_path)
  except Exception as e: # Catch more specific GCS exceptions if possible
    logging.exception('Failed to download %s from bucket %s: %s',
                      gcs_zip_file_path, VULN_BUCKET, e)
    sys.exit(1) # Exit if essential download fails
  logging.info('Successfully downloaded gs://%s/%s to %s.', VULN_BUCKET, gcs_zip_file_path, local_destination_path)


def write_to_json(bug_info_list: List[Dict[str, Optional[str]]]) -> None: # Value can be None
  """Writes list of simplified bug information to multiple JSON files."""
  if not os.path.exists(BUG_DIR): # Ensure base BUG_DIR exists
      os.makedirs(BUG_DIR, exist_ok=True)

  file_counter: int = 0
  for i in range(0, len(bug_info_list), ENTRIES_PER_FILE):
    output_file_name: str = os.path.join(BUG_DIR, f'all_bugs_{file_counter}.json') # Renamed
    try:
      with open(output_file_name, 'w', encoding='utf-8') as f_handle: # Renamed f
        # Extract a slice of the list for the current file
        slice_to_write: List[Dict[str, Optional[str]]] = bug_info_list[i : i + ENTRIES_PER_FILE] # Renamed
        json.dump(slice_to_write, f_handle, indent=2)
      logging.info('Saved %d entries to %s (total processed so far: %d)',
                   len(slice_to_write), output_file_name, min(i + ENTRIES_PER_FILE, len(bug_info_list)))
    except IOError as e: # Catch file I/O errors specifically
      logging.exception("Error writing to JSON file %s: %s", output_file_name, e)
    except TypeError as e: # Catch errors during json.dump if data is not serializable
      logging.exception("TypeError during JSON serialization for %s: %s", output_file_name, e)
    finally: # Ensure file_counter increments even if write fails for one file
      file_counter += 1


def get_bugs_from_export() -> None:
  """Gets all bugs from the exported all.zip, processes them, and writes to BUG_DIR."""
  # Create a persistent temporary directory if it doesn't exist, within BUG_DIR
  # This seems to be for staging the download if tempfile.TemporaryDirectory is not used for download.
  # Original code uses tempfile.TemporaryDirectory for the whole download & processing.
  persistent_tmp_dir = os.path.join(BUG_DIR, 'tmp_download') # Renamed tmp_dir
  os.makedirs(persistent_tmp_dir, exist_ok=True)
  # The `os.environ['TMPDIR'] = persistent_tmp_dir` line is unusual.
  # It changes the system-wide temp dir for processes spawned from here if they use TMPDIR.
  # For tempfile.TemporaryDirectory, `dir` param is better.
  # Let's keep it if it has a specific purpose, but it's not standard for self-contained temp space.

  logging.info('Starting to process %s for bug export.', ZIP_FILE_PATH)

  with tempfile.TemporaryDirectory(dir=persistent_tmp_dir) as temp_extraction_dir: # Renamed tmp_dir
    download_vuln_zip(temp_extraction_dir)
    local_zip_path = os.path.join(temp_extraction_dir, ZIP_FILE_PATH) # Renamed all_zip

    processed_bug_info_list: List[Dict[str, Optional[str]]] = [] # Renamed bug_info_list

    try:
      with zipfile.ZipFile(local_zip_path, 'r') as vuln_zip_file: # Renamed vuln_zip
        for filename_in_zip in vuln_zip_file.namelist(): # Renamed filename
          # Process only JSON files within the zip, assuming they are OSV records
          if not filename_in_zip.endswith('.json'):
              logging.debug("Skipping non-JSON file in zip: %s", filename_in_zip)
              continue
          try:
            with vuln_zip_file.open(filename_in_zip) as file_in_zip: # Renamed file
              # json.load can return Any, expect Dict[str, Any] for OSV record
              bug_data_dict: Dict[str, Any] = json.load(file_in_zip) # Renamed bug
              processed_bug_info_list.append(format_bug_for_output(bug_data_dict))
          except json.JSONDecodeError as e:
            logging.warning('Skipping invalid JSON file %s in zip: %s', filename_in_zip, e)
          except Exception as e: # Catch other errors during file processing within zip
            logging.warning('Error processing file %s in zip: %s', filename_in_zip, e, exc_info=True)

    except zipfile.BadZipFile as e:
        logging.error("Failed to read main zip file %s: %s", local_zip_path, e)
        # No sys.exit here, allow main to handle overall flow or decide if fatal.
        return # Cannot proceed if main zip is bad.

    write_to_json(processed_bug_info_list)
  logging.info('All bug information processed and saved to %s.', BUG_DIR)


def main() -> None:
  osv.logs.setup_gcp_logging('staging-api-test-retriever') # More specific service name

  if not os.path.exists(BUG_DIR):
    logging.info("Bug directory %s does not exist. Proceeding to fetch and process bugs.", BUG_DIR)
    # Initialize random seed once before processing.
    # Using a larger range for seed, and logging it.
    current_seed: int = random.randrange(sys.maxsize) # Renamed seed
    logging.info('Using random seed: %d', current_seed)
    random.seed(current_seed)

    get_bugs_from_export()
    logging.info('Fetching and processing bug data finished.')
  else:
    logging.info('Bug directory %s already exists. Skipping fetching and processing.', BUG_DIR)


if __name__ == '__main__':
  main()
