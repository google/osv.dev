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
"""Frontend handler tests."""
import shutil
import tempfile
import unittest

from google.cloud import ndb

import frontend_handlers
from osv import models
from osv import tests


class FrontendHandlerTest(unittest.TestCase):
  """Frontend handler tests."""

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_ecosystem_counts(self):
    """Test ecosystem counts aggregates correctly updates."""
    models.Bug(
        id='OSV-0',
        db_id='OSV-0',
        status=1,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'PyPI',
                'name': 'blah',
            },
        }]).put()

    models.Bug(
        id='OSV-1',
        db_id='OSV-1',
        status=1,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:3.1',
                'name': 'blah',
            },
        }, {
            'package': {
                'ecosystem': 'Debian:7',
                'name': 'blah',
            },
        }]).put()

    models.Bug(
        id='OSV-2',
        db_id='OSV-2',
        status=1,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:8',
                'name': 'blah',
            },
        }]).put()

    # Invalid entries.
    models.Bug(
        id='OSV-3',
        db_id='OSV-3',
        status=2,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:8',
                'name': 'blah',
            },
        }]).put()

    models.Bug(
        id='OSV-4',
        db_id='OSV-4',
        status=1,
        public=False,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:8',
                'name': 'blah',
            },
        }]).put()

    counts = frontend_handlers.osv_get_ecosystem_counts()
    self.assertDictEqual({'Debian': 2, 'PyPI': 1}, counts)


if __name__ == '__main__':
  ds_emulator = tests.start_datastore_emulator()
  try:
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      unittest.main()
  finally:
    ds_emulator.kill()
