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

from google.cloud import ndb

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
      help='Maximum number of parallel exports',
      default=DEFAULT_EXPORT_PROCESSES)
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  query = osv.Bug.query(projection=[osv.Bug.ecosystem], distinct=True)
  ecosystems = [bug.ecosystem[0] for bug in query if bug.ecosystem] + ["list"]

  with concurrent.futures.ThreadPoolExecutor(
      max_workers=args.processes) as executor:
    for eco in ecosystems:
      executor.submit(spawn_ecosystem_exporter, args.work_dir, args.bucket, eco)


def spawn_ecosystem_exporter(work_dir: str, bucket: str, eco: str):
  """
  Spawns the ecosystem specific exporter.
  """
  logging.info("Starting export of ecosystem: %s", eco)
  proc = subprocess.Popen([
      "exporter.py", "--work_dir", work_dir, "--bucket", bucket, "--ecosystem",
      eco
  ])
  return_code = proc.wait()
  if return_code != 0:
    logging.error(f"Export of {eco} failed with Exit Code: {return_code}")


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('exporter-runner')
  with _ndb_client.context():
    main()
