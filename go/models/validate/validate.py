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
"""Script to ensure datastore definitions in Python and Go are compatible."""
import datetime
import subprocess
import sys

from google.cloud import ndb

import osv.tests
from osv import Vulnerability


def main() -> int:
  # Populate the examples from Python
  print('(Python) Putting Vulnerability')
  Vulnerability(
      id='CVE-123-456',
      source_id='test:path/to/CVE-123-456.json',
      modified=datetime.datetime(2025, 1, 2, 3, 4, 5, tzinfo=datetime.UTC),
      is_withdrawn=False,
      modified_raw=datetime.datetime(2025, 1, 1, 1, 1, 1, tzinfo=datetime.UTC),
      alias_raw=['OSV-123-456', 'TEST-123-456'],
      related_raw=['CVE-000-000', 'CVE-111-111'],
      upstream_raw=['CVE-123-000', 'OSV-123-000'],
  ).put()

  # Run Go program to read the Python-created entities in Go.
  # And write Go entities.
  result = subprocess.run(['go', 'run', './validate.go'], check=False)
  if result.returncode != 0:
    return result.returncode

  # Read the Go-created entities in Python.
  print('(Python) Getting Vulnerability')
  if Vulnerability.get_by_id('CVE-987-654') is None:
    return 1
  return 0


if __name__ == '__main__':
  with osv.tests.datastore_emulator(), ndb.Client().context():
    ret = main()
  sys.exit(ret)
