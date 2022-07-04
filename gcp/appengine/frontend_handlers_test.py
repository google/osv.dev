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
import os
import shutil
import tempfile
import unittest
from unittest import mock

from google.cloud import ndb

import frontend_handlers
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

  @mock.patch('osv.Bug.query')
  @mock.patch('frontend_handlers.osv_get_ecosystems')
  def test_ecosystem_counts(self, mock_osv_get_ecosystems: mock.Mock,
                            mock_query: mock.Mock):
    """Test ecosystem counts aggregates correctly updates."""

    mock_osv_get_ecosystems.return_value = [
        'Android', 'Debian:3.1', 'Debian:7', 'npm'
    ]
    mock_query.return_value.count.return_value = 4

    counts = frontend_handlers.osv_get_ecosystem_counts()

    mock_osv_get_ecosystems.assert_called_once()
    self.assertDictEqual(counts, {'Android': 4, 'Debian': 8, 'npm': 4})


if __name__ == '__main__':
  os.system('pkill -f datastore')
  ds_emulator = tests.start_datastore_emulator()
  try:
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      unittest.main()
  finally:
    # TODO(ochang): Cleaner way of properly cleaning up processes.
    os.system('pkill -f datastore')
