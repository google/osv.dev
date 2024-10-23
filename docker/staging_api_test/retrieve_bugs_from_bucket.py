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

import logging
import os
import random
import json
import tempfile
import zipfile

import osv.logs

from google.cloud import storage

GCP_PROJECT = 'oss-vdb-test'
BUG_DIR = './all_bugs'
VULN_BUCKET = 'osv-test-vulnerabilities'
ZIP_FILE_PATH = 'all.zip'

def format_bug_for_output(bug: dict[str, any]) -> dict[str, any]:
  """Extracts relevant information from a vulnerability record.

  This function processes a vulnerability record and extracts specific fields
  needed for further api query usage.

  Args:
    bug: a vulnerability record.

  Returns:
    A dict storing all the important `Bug` fields that we want to use later
  """
  if not bug.get('affected'):
    return {
      'db_id': bug['id']
    }

  affected_fuzzy = None
  affected = random.choice(bug['affected'])
  affected_package = affected.get('package')
  if not affected_package:
    return {
      'db_id': bug['id']
    }

  # Store one version for use as the query version later.
  if affected.get('versions'):
    affected_fuzzy = random.choice(affected['versions'])

  if not affected_fuzzy and affected.get('ranges'):
    range_item = random.choice(affected['ranges'])
    if range_item and range_item.get('events'):
      event = random.choice(range_item['events'])
      if event:
        affected_fuzzy = random.choice(list(event.values()))

  return {
      'db_id': bug['id'],
      'project': affected_package.get('name', None),
      'ecosystem': affected_package.get('ecosystem', None),
      'affected_fuzzy': affected_fuzzy
  }

def download_vuln_zip(tmp_dir: str) -> None:
  """Downloads all.zip file from bucket."""
  logging.info('Start to download %s.', ZIP_FILE_PATH)
  storage_client = storage.Client()
  bucket = storage_client.get_bucket(VULN_BUCKET)
  try:
    blob = bucket.blob(ZIP_FILE_PATH)
    file_path = os.path.join(tmp_dir, ZIP_FILE_PATH)  
    blob.download_to_filename(file_path)
  except Exception as e:
    logging.exception('Failed to download all.zip: %s', e)
  logging.info('Downloaded %s.', ZIP_FILE_PATH)

def get_bugs_from_export() -> None:
  """Gets all bugs from the exported all.zip and writes to `BUG_DIR`."""

  entries_per_file = 10000  # amount of bugs per file
  file_counter = 0
  os.makedirs(BUG_DIR, exist_ok=True)
  tmp_dir = os.path.join(BUG_DIR, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir
  logging.info('Start to process %s.', ZIP_FILE_PATH)

  def write_to_json():
    """Writes to a new JSON file."""
    file_name = f'{BUG_DIR}/all_bugs_{file_counter}.json'
    with open(file_name, 'w+') as f:
      json.dump(bug_info_list, f, indent=2)
    logging.info('Saved %d entries to %s', len(bug_info_list), file_name)

  with tempfile.TemporaryDirectory() as tmp_dir:
    download_vuln_zip(tmp_dir)
    all_zip = os.path.join(tmp_dir, ZIP_FILE_PATH)
    bug_info_list = []
    with zipfile.ZipFile(all_zip, 'r') as zip:
      for filename in zip.namelist():
        try:
          with zip.open(filename) as file:
            bug = json.load(file)
            bug_info_list.append(format_bug_for_output(bug))
            if len(bug_info_list) == entries_per_file:
              write_to_json()
              file_counter += 1
              bug_info_list = []
        except Exception as e:
          logging.warning('Skipping invalid JSON file %s: %s', filename, e)
          continue

  logging.info('All results saved to %s.', BUG_DIR)

def main() -> None:
  osv.logs.setup_gcp_logging('staging-test')

  if not os.path.exists(BUG_DIR):
    # This will take around 10 mins
    seed = random.randrange(100)
    # The seed value can be replaced for debugging
    random.seed(seed)
    logging.info('Random seed %d', seed)
    get_bugs_from_export()
    logging.info('Fetching data finished.')
  else:
    logging.info('%s exists, skipping fetching.', BUG_DIR)


if __name__ == '__main__':
  main()
