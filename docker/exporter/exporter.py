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
import shutil
import tempfile
import zipfile
from typing import List

from google.cloud import ndb
from google.cloud import storage

import osv
import osv.logs

DEFAULT_WORK_DIR = '/work'

DEFAULT_EXPORT_BUCKET = 'osv-vulnerabilities'
_EXPORT_WORKERS = 32
ECOSYSTEMS_FILE = 'ecosystems.txt'


class Exporter:
  """Exporter."""

  def __init__(self, work_dir, export_bucket):
    self._work_dir = work_dir
    self._export_bucket = export_bucket

  def run(self):
    """Run exporter."""
    query = osv.Bug.query(projection=[osv.Bug.ecosystem], distinct=True)
    ecosystems = [bug.ecosystem[0] for bug in query if bug.ecosystem]

    for ecosystem in ecosystems:
      with tempfile.TemporaryDirectory() as tmp_dir:
        self._export_ecosystem_to_bucket(ecosystem, tmp_dir)

    with tempfile.TemporaryDirectory() as tmp_dir:
      self._export_ecosystem_list_to_bucket(ecosystems, tmp_dir)

  def upload_single(self, bucket, source_path, target_path):
    """Upload a single file to a bucket."""
    logging.info('Uploading %s', target_path)
    try:
      blob = bucket.blob(target_path)
      blob.upload_from_filename(source_path)
    except Exception as e:
      logging.error('Failed to export: %s', e)

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

  def _export_ecosystem_to_bucket(self, ecosystem, tmp_dir):
    """Export ecosystem vulns to bucket."""
    logging.info('Exporting vulnerabilities for ecosystem %s', ecosystem)
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(self._export_bucket)

    zip_path = os.path.join(tmp_dir, 'all.zip')
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:

      @ndb.tasklet
      def _exporter_file(bug):
        if not bug.public or bug.status == osv.BugStatus.UNPROCESSED:
          return

        file_path = os.path.join(tmp_dir, bug.id() + '.json')
        vulnerability = bug.to_vulnerability(
            include_source=True, include_alias=False)
        alias_group = yield osv.get_aliases_async(vulnerability.id)
        if alias_group:
          alias_ids = sorted(
              list(set(alias_group.bug_ids) - {vulnerability.id}))
          vulnerability.aliases[:] = alias_ids
          modified_time = vulnerability.modified.ToDatetime()
          modified_time = max(alias_group.last_modified, modified_time)
          vulnerability.modified.FromDatetime(modified_time)
        related_bug_ids = yield osv.get_related_async(vulnerability.id)
        vulnerability.related[:] = sorted(
            list(set(related_bug_ids + list(vulnerability.related))))
        osv.write_vulnerability(vulnerability, file_path)
        # Tasklets are not truly multiple threads;they are actually
        # event loops, which makes it safe to write to ZIP files."
        # Details: https://cloud.google.com/appengine/docs/legacy/
        # standard/python/ndb/async#tasklets
        zip_file.write(file_path, os.path.basename(file_path))

      osv.Bug.query(osv.Bug.ecosystem == ecosystem).map(_exporter_file)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_EXPORT_WORKERS) as executor:
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
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  # Temp files are on the persistent local SSD,
  # and they do not get removed when GKE sends a SIGTERM to stop the pod.
  # Manually clear the tmp_dir folder of any leftover files
  # TODO(michaelkedar): use an ephemeral disk for temp storage.
  if os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  exporter = Exporter(args.work_dir, args.bucket)
  exporter.run()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('exporter')
  with _ndb_client.context():
    main()
