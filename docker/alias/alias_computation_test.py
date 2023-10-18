# Copyright 2023 Google LLC
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
"""Alias computation tests."""
import datetime
import os
import unittest

from google.cloud import ndb

import osv
from docker.alias import alias_computation
from osv import tests

TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')


class AliasTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Alias tests."""

  def test_basic(self):
    """Tests basic case."""
    osv.AliasGroup(
        bug_ids=['aaa-123', 'aaa-124'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    bug_ids = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'aaa-123').get().bug_ids
    self.assertEqual(['aaa-123', 'aaa-124'], bug_ids)

  def test_update_alias_group(self):
    """Tests updating an existing alias group."""
    osv.AliasGroup(
        bug_ids=['bbb-123', 'bbb-234'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='bbb-123',
        db_id='bbb-123',
        aliases=['bbb-345', 'bbb-456'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='bbb-789',
        db_id='bbb-789',
        aliases=['bbb-456'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'bbb-123').get()
    self.assertEqual(['bbb-123', 'bbb-234', 'bbb-345', 'bbb-456', 'bbb-789'],
                     alias_group.bug_ids)
    self.assertNotEqual(
        datetime.datetime(2023, 1, 1), alias_group.last_modified)

  def test_create_alias_group(self):
    """Tests adding a new alias group."""
    osv.Bug(
        id='test-123',
        db_id='test-123',
        aliases=['test-124'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='test-222',
        db_id='test-222',
        aliases=['test-124'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'test-123').get()
    self.assertIsNotNone(alias_group)
    self.assertEqual(['test-123', 'test-124', 'test-222'], alias_group.bug_ids)

  def test_delete_alias_group(self):
    """Tests deleting alias groups that only has one vulnerability."""
    osv.Bug(
        id='ccc-123',
        db_id='ccc-123',
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['ccc-123'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'ccc-123').get()
    self.assertIsNone(alias_group)


if __name__ == '__main__':
  os.system('pkill -f datastore')
  ds_emulator = tests.start_datastore_emulator()
  try:
    with ndb.Client().context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      unittest.main()
  finally:
    os.system('pkill -f datastore')
