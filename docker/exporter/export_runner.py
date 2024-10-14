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
"""OSV Exporter."""
import argparse
import concurrent.futures
import logging
import os
import subprocess
import shutil
import zipfile as z

from google.cloud import ndb, storage

from exporter import upload_single
import osv
import osv.logs

DEFAULT_WORK_DIR = '/work'
DEFAULT_EXPORT_BUCKET = 'osv-vulnerabilities'
DEFAULT_EXPORT_PROCESSES = 7


def main():
  parser = argparse.ArgumentParser(description='Exporter')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument(
      '--bucket',
      help='Bucket name to export to',
      default=DEFAULT_EXPORT_BUCKET)
  parser.add_argument(
      '--processes',
      help='Maximum number of parallel exports, default to number of cpu cores',
      # If 0 or None, use the DEFAULT_EXPORT_PROCESSES value
      default=os.cpu_count() or DEFAULT_EXPORT_PROCESSES)
  args = parser.parse_args()

  # Clean up the work directory, in case other job didn't clean it properly.
  clean_work_dir(args.work_dir)
  query = osv.Bug.query(projection=[osv.Bug.ecosystem], distinct=True)
  ecosystems = [bug.ecosystem[0] for bug in query if bug.ecosystem] + ['list']

  with concurrent.futures.ThreadPoolExecutor(
      max_workers=args.processes) as executor:
    for eco in ecosystems:
      # Skip exporting data for child ecosystems (e.g., 'Debian:11').
      if ':' in eco:
        continue
      executor.submit(spawn_ecosystem_exporter, args.work_dir, args.bucket, eco)
  # Upload a ZIP file containing records from all ecosystems.
  aggregate_all_vulnerabilities(args.work_dir, args.bucket)
  clean_work_dir(args.work_dir)


def spawn_ecosystem_exporter(work_dir: str, bucket: str, eco: str):
  """
  Spawns the ecosystem specific exporter.
  """
  logging.info('Starting export of ecosystem: %s', eco)
  proc = subprocess.Popen([
      'exporter.py', '--work_dir', work_dir, '--bucket', bucket, '--ecosystem',
      eco
  ])
  return_code = proc.wait()
  if return_code != 0:
    logging.error('Export of %s failed with Exit Code: %d', eco, return_code)


def aggregate_all_vulnerabilities(work_dir: str, export_bucket: str):
  """
  Aggregates vulnerability records from each ecosystem into a single zip
  file and uploads it to the export bucket.
  """
  zip_file_name = 'all.zip'
  output_zip = os.path.join(work_dir, zip_file_name)
  all_vulns = {}

  for ecosystem_dir, _, files in os.walk(work_dir):
    if ecosystem_dir == work_dir:
      continue
    for vuln_filename in files:
      if not vuln_filename.endswith('.json'):
        continue
      all_vulns[vuln_filename] = os.path.join(ecosystem_dir, vuln_filename)

  with z.ZipFile(output_zip, 'a') as all_zip:
    for vuln_filename in sorted(all_vulns):
      file_path = all_vulns[vuln_filename]
      all_zip.write(file_path, os.path.basename(file_path))

  storage_client = storage.Client()
  bucket = storage_client.get_bucket(export_bucket)
  upload_single(bucket, output_zip, zip_file_name)


def clean_work_dir(work_dir: str):
  if os.path.exists(work_dir):
    shutil.rmtree(work_dir, ignore_errors=True)
  os.makedirs(work_dir, exist_ok=True)  # Recreate the directory (empty one)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('exporter-runner')
  with _ndb_client.context():
    main()
