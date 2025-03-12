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
import argparse
import concurrent.futures
import logging
import os
import zipfile
from typing import List

from google.cloud import ndb
from google.cloud import storage
from google.cloud.storage import retry
from google.cloud.storage.bucket import Bucket

import requests

import osv
import osv.logs

DEFAULT_WORK_DIR = '/work'

DEFAULT_EXPORT_BUCKET = 'osv-vulnerabilities'
DEFAULT_SAFE_DELTA_PCT = 10
_EXPORT_WORKERS = 32
ECOSYSTEMS_FILE = 'ecosystems.txt'


class Error(Exception):
  """Base exception class."""


def modify_storage_client_adapters(storage_client: storage.Client,
                                   pool_connections: int = 128,
                                   max_retries: int = 3,
                                   pool_block: bool = True) -> storage.Client:
  """In-place modifies the adapters of a google.cloud.storage.Client object.

  Due to the concurrent GCS connections, the default connection pool can become
  overwhelmed, introducing delays.

  Solution described in https://github.com/googleapis/python-storage/issues/253

  These affect the urllib3.HTTPConnectionPool underpinning the storage.Client's
  HTTP requests.

  Args:
    storage_client: an existing google.cloud.storage.Client object
    pool_connections: number of pool_connections desired
    max_retries: maximum retries
    pool_block: blocking behaviour when pool is exhausted

  Returns:
    the google.cloud.storage.Client appropriately modified.

  """
  adapter = requests.adapters.HTTPAdapter(
      pool_connections=pool_connections,
      max_retries=max_retries,
      pool_block=pool_block)
  # pylint: disable=protected-access
  storage_client._http.mount('https://', adapter)
  storage_client._http._auth_request.session.mount('https://', adapter)
  return storage_client


class Exporter:
  """Exporter."""

  def __init__(self, work_dir, export_bucket, ecosystem):
    self._work_dir = work_dir
    self._export_bucket = export_bucket
    self._ecosystem = ecosystem

  def run(self):
    """Run exporter."""
    if self._ecosystem == "list":
      query = osv.Bug.query(projection=[osv.Bug.ecosystem], distinct=True)
      # Filter out ecosystems that contain a colon,
      # as these represent Linux distro releases.
      ecosystems = [
          bug.ecosystem[0]
          for bug in query
          if bug.ecosystem and ':' not in bug.ecosystem[0]
      ]
      self._export_ecosystem_list_to_bucket(ecosystems, self._work_dir)
    else:
      self._export_ecosystem_to_bucket(self._ecosystem, self._work_dir)

  def _export_ecosystem_list_to_bucket(self, ecosystems: List[str],
                                       tmp_dir: str):
    """Export an ecosystems.txt file with all of the ecosystem names.

    See https://github.com/google/osv.dev/issues/619

    Args:
      ecosystems: the list of ecosystem names
      tmp_dir: temporary directory for scratch
    """

    logging.info('Exporting ecosystem list to %s', ECOSYSTEMS_FILE)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(self._export_bucket)
    ecosystems_file_path = os.path.join(tmp_dir, ECOSYSTEMS_FILE)
    with open(ecosystems_file_path, "w") as ecosystems_file:
      ecosystems_file.writelines([e + "\n" for e in ecosystems])

    upload_single(bucket, ecosystems_file_path, ECOSYSTEMS_FILE)

  def _export_ecosystem_to_bucket(self, ecosystem: str, work_dir: str):
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
    storage_client = storage.Client()
    storage_client = modify_storage_client_adapters(storage_client)
    bucket = storage_client.get_bucket(self._export_bucket)

    ecosystem_dir = os.path.join(work_dir, ecosystem)
    os.makedirs(ecosystem_dir, exist_ok=True)
    zip_path = os.path.join(ecosystem_dir, 'all.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
      files_to_zip = []

      @ndb.tasklet
      def _export_to_file_and_zipfile(bug: osv.Bug):
        """Write out a bug record to both a single file and the zip file."""
        if not bug.public or bug.status == osv.BugStatus.UNPROCESSED:
          return

        try:
          file_path = os.path.join(ecosystem_dir, bug.id() + '.json')
          vulnerability = yield bug.to_vulnerability_async(
              include_source=True, include_alias=True, include_upstream=True)
          osv.write_vulnerability(vulnerability, file_path)

          files_to_zip.append(file_path)
        except Exception:
          logging.exception('Failed to export bug: "%s"', bug.id())
          raise

      # This *should* pause here until
      # all the exports have been written to disk.
      osv.Bug.query(
          osv.Bug.ecosystem == ecosystem).map(_export_to_file_and_zipfile)

      files_to_zip.sort()
      for file_path in files_to_zip:
        zip_file.write(file_path, os.path.basename(file_path))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_EXPORT_WORKERS) as executor:
      # Note: the individual ecosystem all.zip is included here
      # TODO: use safe_upload_single() on the zip files.
      for filename in os.listdir(ecosystem_dir):
        executor.submit(upload_single, bucket,
                        os.path.join(ecosystem_dir, filename),
                        f'{ecosystem}/{filename}')


def upload_single(bucket: Bucket, source_path: str, target_path: str):
  """Upload a single file to a GCS bucket."""
  logging.info('Uploading %s', target_path)
  try:
    blob = bucket.blob(target_path)
    blob.upload_from_filename(source_path, retry=retry.DEFAULT_RETRY)
  except Exception as e:
    logging.exception('Failed to export: %s', e)


def safe_upload_single(bucket: Bucket,
                       source_path: str,
                       target_path: str,
                       safe_delta_pct: int = DEFAULT_SAFE_DELTA_PCT):
  """Upload a single file to a GCS bucket, with a size check.

  This refuses to overwrite the GCS object if the file size difference is
  greater than the permitted threshold (10% by default).

  NOTE: this intentionally only catches unexpectedly smaller files, not larger
  ones.

  Args:
    bucket: (Bucket): the GCS bucket object to upload to.
    source_path: (str): the source path to the file to upload.
    target_path: (str): the target path in Bucket to upload to.
    safe_delta_pct: (int): the threshold at which to raise an exception.

  Raises:
    Error: if safe_delta_pct is exceeded
  """

  source_size = os.stat(source_path).st_size
  logging.info('Uploading %s', target_path)
  try:
    blob = bucket.get_blob(target_path)
    if blob and blob.size and (source_size / blob.size) * 100 < safe_delta_pct:
      raise (Error(
          f'Cowardly refusing to overwrite {blob.name} ({blob.size} bytes) '
          f'with {source_path} ({source_size} bytes)'))
    if blob:
      blob.upload_from_filename(source_path, retry=retry.DEFAULT_RETRY)
  except Exception as e:
    logging.exception('Failed to export: %s', e)


def main():
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
