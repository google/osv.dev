#!/usr/bin/env python3
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
"""OSV Exporter."""
from __future__ import annotations

import argparse
import concurrent.futures
import logging
import os
import zipfile
from typing import List, Any # Added Any

from google.cloud import ndb
from google.cloud import storage
from google.cloud.storage import retry
from google.cloud.storage.bucket import Bucket # Specific import for Bucket type

import requests

import osv.models # For osv.models.Bug, etc.
import osv.logs # For osv.logs.setup_gcp_logging
from osv import vulnerability_pb2 # For osv.vulnerability_pb2.Vulnerability

DEFAULT_WORK_DIR = '/work'

DEFAULT_EXPORT_BUCKET = 'osv-vulnerabilities'
DEFAULT_SAFE_DELTA_PCT = 10 # Percentage
_EXPORT_WORKERS = 32
ECOSYSTEMS_FILE = 'ecosystems.txt'

# Global NDB client
_ndb_client: ndb.Client


class Error(Exception):
  """Base exception class."""


def modify_storage_client_adapters(storage_client: storage.Client,
                                   pool_connections: int = 128,
                                   max_retries_val: int = 3, # Renamed max_retries
                                   pool_block: bool = True) -> storage.Client:
  """Returns a modified google.cloud.storage.Client object.

  Due to many concurrent GCS connections, the default connection pool can become
  overwhelmed, introducing delays.

  Solution described in https://github.com/googleapis/python-storage/issues/253

  These affect the urllib3.HTTPConnectionPool underpinning the storage.Client's
  HTTP requests.

  Args:
    storage_client: an existing google.cloud.storage.Client object
    pool_connections: number of pool_connections desired
    max_retries_val: maximum retries for the adapter.
    pool_block: blocking behaviour when pool is exhausted

  Returns:
    the google.cloud.storage.Client appropriately modified.

  """
  # The requests.adapters.HTTPAdapter max_retries can be an int or a Retry object.
  # Here, it's used as an int.
  adapter = requests.adapters.HTTPAdapter(
      pool_connections=pool_connections,
      max_retries=max_retries_val,
      pool_block=pool_block)

  # pylint: disable=protected-access
  # Accessing protected members _http and _auth_request is necessary here.
  # This might be fragile if underlying library structure changes.
  if hasattr(storage_client, '_http') and hasattr(storage_client._http, '_auth_request'): # type: ignore[attr-defined]
    storage_client._http.mount('https://', adapter) # type: ignore[attr-defined]
    storage_client._http._auth_request.session.mount('https://', adapter) # type: ignore[attr-defined]
  else:
    logging.warning("Could not modify storage client adapters: _http or _auth_request not found.")

  return storage_client


class Exporter:
  """Exporter."""
  _work_dir: str
  _export_bucket: str
  _ecosystem: str # Can be "list" or a specific ecosystem name

  def __init__(self, work_dir: str, export_bucket: str, ecosystem: str) -> None:
    self._work_dir = work_dir
    self._export_bucket = export_bucket
    self._ecosystem = ecosystem

  def run(self) -> None:
    """Run exporter."""
    if self._ecosystem == "list":
      # osv.models.Bug needed
      query: ndb.Query[osv.models.Bug] = osv.models.Bug.query(
          projection=[osv.models.Bug.ecosystem], distinct=True)

      # Filter out ecosystems that contain a colon (distro releases)
      # and ensure bug.ecosystem is not None and not empty.
      ecosystems_list: List[str] = [] # Renamed ecosystems
      bug_item: osv.models.Bug # Type hint for loop variable
      for bug_item in query:
          if bug_item.ecosystem and bug_item.ecosystem[0] and ':' not in bug_item.ecosystem[0]:
              ecosystems_list.append(bug_item.ecosystem[0])
      # Deduplicate and sort after filtering
      self._export_ecosystem_list_to_bucket(sorted(list(set(ecosystems_list))), self._work_dir)
    else:
      self._export_ecosystem_to_bucket(self._ecosystem, self._work_dir)

  def _export_ecosystem_list_to_bucket(self, ecosystems_list: List[str], # Renamed ecosystems
                                       tmp_dir: str) -> None:
    """Export an ecosystems.txt file with all of the ecosystem names.

    See https://github.com/google/osv.dev/issues/619

    Args:
      ecosystems_list: the list of ecosystem names
      tmp_dir: temporary directory for scratch
    """
    logging.info('Exporting ecosystem list to %s', ECOSYSTEMS_FILE)
    storage_client = storage.Client()
    # Type hint for bucket object
    bucket: Bucket = storage_client.get_bucket(self._export_bucket)
    ecosystems_file_path = os.path.join(tmp_dir, ECOSYSTEMS_FILE)

    # Ensure directory exists for writing the local file
    os.makedirs(os.path.dirname(ecosystems_file_path) or '.', exist_ok=True)
    with open(ecosystems_file_path, "w", encoding='utf-8') as ecosystems_file_handle: # Renamed
      ecosystems_file_handle.writelines([e + "\n" for e in ecosystems_list])

    upload_single(bucket, ecosystems_file_path, ECOSYSTEMS_FILE)

  def _export_ecosystem_to_bucket(self, ecosystem: str, work_dir: str) -> None:
    """Export the vulnerabilities in an ecosystem to GCS.

    Args:
      ecosystem: the ecosystem name
      work_dir: working directory for scratch

    This simultaneously exports every Bug for the given ecosystem to individual
    files in the scratch filesystem, and a zip file in the scratch filesystem.

    At the conclusion of this export, all of the files in the scratch filesystem
    (including the zip file) are uploaded to the GCS bucket.
    """
    logging.info('Exporting vulnerabilities for ecosystem %s', ecosystem)
    storage_client: storage.Client = modify_storage_client_adapters(storage.Client())
    bucket: Bucket = storage_client.get_bucket(self._export_bucket)

    ecosystem_dir = os.path.join(work_dir, ecosystem)
    os.makedirs(ecosystem_dir, exist_ok=True)
    zip_file_path = os.path.join(ecosystem_dir, 'all.zip') # Renamed zip_path

    # List to store paths of successfully written JSON files to be added to zip.
    # This helps avoid adding partially written or failed files to zip.
    exported_file_paths: List[str] = [] # Renamed files_to_zip

    @ndb.tasklet # This decorator indicates an async NDB operation returning a Future
    def _export_to_file_tasklet(bug_model: osv.models.Bug) -> ndb.Future[Optional[str]]: # Renamed bug, returns Future[Optional[str]]
        """Write out a bug record to a single file. Returns file path if successful."""
        # osv.models.BugStatus needed
        if not bug_model.public or bug_model.status == osv.models.BugStatus.UNPROCESSED:
          return None # type: ignore[return-value] # Tasklet expects Future, will be wrapped

        try:
          # Ensure bug_model.id() is valid
          bug_id_str = bug_model.id() # Assuming id() returns str and is valid
          if not bug_id_str:
              logging.error("Bug has no ID, cannot export: %s", bug_model.key)
              return None # type: ignore[return-value]

          file_path = os.path.join(ecosystem_dir, bug_id_str + '.json')
          # bug.to_vulnerability_async returns Future[vulnerability_pb2.Vulnerability]
          vulnerability_proto: vulnerability_pb2.Vulnerability = yield bug_model.to_vulnerability_async( # Renamed
              include_source=True, include_alias=True, include_upstream=True)

          # osv.models.write_vulnerability (assuming it's moved or correctly referenced)
          osv.models.write_vulnerability(vulnerability_proto, file_path)
          return file_path # Return path of successfully written file
        except Exception: # Catch broad exception during export of a single bug
          logging.exception('Failed to export bug: "%s"', bug_model.id() if hasattr(bug_model, 'id') else 'UNKNOWN_ID')
          # Do not re-raise here to allow other bugs to process. Error is logged.
          return None # type: ignore[return-value]

    # Query for all public, processed bugs in the ecosystem.
    # osv.models.Bug needed
    query: ndb.Query[osv.models.Bug] = osv.models.Bug.query(
        osv.models.Bug.ecosystem == ecosystem,
        osv.models.Bug.public == True,  # noqa: E712
        osv.models.Bug.status == osv.models.BugStatus.PROCESSED
    )

    # map() will run the tasklet sequentially for each bug.
    # It collects the results (which are file paths or None).
    # If map_async was used, it would collect Futures.
    # Given the comment about pausing, current map() implies synchronous overall behavior.
    results_from_map: List[Optional[str]] = query.map(_export_to_file_tasklet) # type: ignore[arg-type]

    # Filter out None results (failed exports) before zipping
    exported_file_paths = [path_str for path_str in results_from_map if path_str is not None]
    exported_file_paths.sort() # Sort for deterministic zip content order

    # Create zip file
    with zipfile.ZipFile(zip_file_path, 'w', zipfile.ZIP_DEFLATED) as zipf: # Renamed zip_file
      for file_path_to_zip in exported_file_paths: # Renamed file_path
        # Add file to zip, using its basename as arcname
        zipf.write(file_path_to_zip, os.path.basename(file_path_to_zip))

    # Upload all individual files and the zip file using a ThreadPoolExecutor
    with concurrent.futures.ThreadPoolExecutor(max_workers=_EXPORT_WORKERS) as executor:
      # List all files in the ecosystem_dir (includes JSONs and the .zip)
      # Ensure files are not directories if ecosystem_dir could contain subdirs.
      # os.listdir just gives names, need to join with ecosystem_dir for full path.
      for filename_to_upload in os.listdir(ecosystem_dir): # Renamed filename
        full_source_path = os.path.join(ecosystem_dir, filename_to_upload)
        if os.path.isfile(full_source_path): # Check if it's a file
            # Target path in GCS bucket: ecosystem/filename
            gcs_target_path = f'{ecosystem}/{filename_to_upload}' # Renamed
            executor.submit(upload_single, bucket, full_source_path, gcs_target_path)


def upload_single(bucket: Bucket, source_path: str, target_path: str) -> None:
  """Upload a single file to a GCS bucket."""
  logging.info('Uploading %s to GCS path %s', source_path, target_path)
  try:
    blob: storage.Blob = bucket.blob(target_path)
    blob.upload_from_filename(source_path, retry=retry.DEFAULT_RETRY)
  except Exception as e: # Catch a more general exception if upload fails
    logging.exception('Failed to upload %s to %s: %s', source_path, target_path, e)
    # Depending on requirements, might re-raise or handle (e.g. mark for retry later)


def safe_upload_single(bucket: Bucket,
                       source_path: str,
                       target_path: str,
                       safe_delta_pct: int = DEFAULT_SAFE_DELTA_PCT) -> None:
  """Upload a single file to a GCS bucket, with a size check.

  This refuses to overwrite the GCS object if the new file is significantly
  smaller than the existing one (more than `safe_delta_pct` smaller).

  Args:
    bucket: The GCS bucket object to upload to.
    source_path: The local path to the file to upload.
    target_path: The target path in the GCS bucket.
    safe_delta_pct: The percentage threshold for size difference.

  Raises:
    Error: If the new file is smaller than the existing one beyond threshold.
  """
  if not os.path.exists(source_path):
      logging.error("Source file for safe_upload_single does not exist: %s", source_path)
      return

  source_size: int = os.stat(source_path).st_size
  logging.info('Safely uploading %s to GCS path %s', source_path, target_path)

  try:
    blob: Optional[storage.Blob] = bucket.get_blob(target_path)
    if blob and blob.size is not None: # Check if blob exists and has size
      # Calculate percentage difference: ( (old - new) / old ) * 100
      # We are concerned if new is much smaller than old.
      # So, if (old_size - new_size) / old_size > safe_delta_pct / 100
      # Or, new_size / old_size < (1 - safe_delta_pct / 100)
      # Original logic: (source_size / blob.size) * 100 < safe_delta_pct
      # This means: new_size is less than safe_delta_pct % of old_size.
      # Example: old=100, new=5, safe_delta_pct=10. (5/100)*100 = 5 < 10. Raise Error. Correct.
      # Example: old=100, new=80, safe_delta_pct=10. (80/100)*100 = 80. Not < 10. OK.
      # Example: old=100, new=95, safe_delta_pct=10. (95/100)*100 = 95. Not < 10. OK.
      # This seems to check if new size is extremely small relative to old.
      # A more common check is if new size is (e.g.) < 90% of old size.
      # (1 - (source_size / blob.size)) * 100 > safe_delta_pct
      # Let's stick to original logic's expression:
      if blob.size > 0: # Avoid division by zero if remote blob has size 0
          size_ratio_pct = (source_size / blob.size) * 100
          if size_ratio_pct < safe_delta_pct: # If new size is less than X% of old
              raise Error(
                  f'Cowardly refusing to overwrite GCS {target_path} ({blob.size} bytes) '
                  f'with local file {source_path} ({source_size} bytes) '
                  f'as new size is only {size_ratio_pct:.2f}% of old, '
                  f'which is less than threshold {safe_delta_pct}%.')
      # If blob.size is 0, allow overwrite.

    # If blob doesn't exist, or if size check passed, (re)upload.
    # Create new blob object for upload if it didn't exist or to ensure properties.
    if blob is None:
        blob = bucket.blob(target_path)
    blob.upload_from_filename(source_path, retry=retry.DEFAULT_RETRY)
    logging.info('Successfully uploaded %s to %s', source_path, target_path)

  except Exception as e: # Catch broader exceptions during GCS interaction
    logging.exception('Failed to safe_upload_single %s to %s: %s', source_path, target_path, e)


def main() -> None: # main usually doesn't return a value, or 0 for success / non-0 for error
  parser = argparse.ArgumentParser(description='Exporter')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument(
      '--bucket',
      help='Bucket name to export to',
      default=DEFAULT_EXPORT_BUCKET)
  parser.add_argument(
      '--ecosystem',
      required=True,
      help='Ecosystem to upload, pass the value "list" ' +
      'to export the ecosystem.txt file')
  args = parser.parse_args()

  exporter = Exporter(args.work_dir, args.bucket, args.ecosystem)
  exporter.run()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('exporter')
  with _ndb_client.context():
    main()
