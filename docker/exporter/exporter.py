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
import tempfile
import zipfile
from typing import List

from google.cloud import ndb
from google.cloud import storage
from google.cloud.storage import retry

import osv
import osv.logs

DEFAULT_WORK_DIR = '/work'

DEFAULT_EXPORT_BUCKET = 'osv-vulnerabilities'
_EXPORT_WORKERS = 32
ECOSYSTEMS_FILE = 'ecosystems.txt'


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
      #TODO(gongh@): remove all ecosystem releases from ecosystem.txt
      # after notifying users.
      ecosystems = [bug.ecosystem[0] for bug in query if bug.ecosystem]
      with tempfile.TemporaryDirectory() as tmp_dir:
        self._export_ecosystem_list_to_bucket(ecosystems, tmp_dir)
    else:
      with tempfile.TemporaryDirectory() as tmp_dir:
        self._export_ecosystem_to_bucket(self._ecosystem, tmp_dir)

  def upload_single(self, bucket, source_path, target_path):
    """Upload a single file to a GCS bucket."""
    logging.info('Uploading %s', target_path)
    try:
      blob = bucket.blob(target_path)
      blob.upload_from_filename(source_path, retry=retry.DEFAULT_RETRY)
    except Exception as e:
      logging.exception('Failed to export: %s', e)

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

    self.upload_single(bucket, ecosystems_file_path, ECOSYSTEMS_FILE)

  def _export_ecosystem_to_bucket(self, ecosystem: str, tmp_dir: str):
    """Export the vulnerabilities in an ecosystem to GCS.

    Args:
      ecosystem: the ecosystem name
      tmp_dir: temporary directory for scratch

    This simultaneously exports every Bug for the given ecosystem to individual
    files in the scratch filesystem, and a zip file in the scratch filesystem.

    At the conclusion of this export, all of the files in the scratch filesystem
    (including the zip file) are uploaded to the GCS bucket.
    """
    logging.info('Exporting vulnerabilities for ecosystem %s', ecosystem)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(self._export_bucket)

    zip_path = os.path.join(tmp_dir, 'all.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
      files_to_zip = []

      @ndb.tasklet
      def _export_to_file_and_zipfile(bug):
        """Write out a bug record to both a single file and the zip file."""
        if not bug.public or bug.status == osv.BugStatus.UNPROCESSED:
          return

        file_path = os.path.join(tmp_dir, bug.id() + '.json')
        vulnerability = yield bug.to_vulnerability_async(include_source=True)
        osv.write_vulnerability(vulnerability, file_path)

        files_to_zip.append(file_path)

      # This *should* pause here until
      # all the exports have been written to disk.
      osv.Bug.query(
          osv.Bug.ecosystem == ecosystem).map(_export_to_file_and_zipfile)

      files_to_zip.sort()
      for file_path in files_to_zip:
        zip_file.write(file_path, os.path.basename(file_path))

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_EXPORT_WORKERS) as executor:
      # Note: all.zip is included here
      for filename in os.listdir(tmp_dir):
        executor.submit(self.upload_single, bucket,
                        os.path.join(tmp_dir, filename),
                        f'{ecosystem}/{filename}')


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

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.environ['TMPDIR'] = tmp_dir

  exporter = Exporter(args.work_dir, args.bucket, args.ecosystem)
  exporter.run()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('exporter')
  with _ndb_client.context():
    main()
