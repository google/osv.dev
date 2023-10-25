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
    osv.Bug(
        id='aaa-123',
        db_id='aaa-123',
        aliases=['aaa-124'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='aaa-124',
        db_id='aaa-124',
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['aaa-123', 'aaa-124'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    bug_ids = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'aaa-123').get().bug_ids
    self.assertEqual(['aaa-123', 'aaa-124'], bug_ids)

  def test_bug_reaches_limit(self):
    """Tests bug reaches limit."""
    osv.Bug(
        id='aaa-111',
        db_id='aaa-111',
        aliases=[
            'aaa-222', 'aaa-333', 'aaa-444', 'aaa-555', 'aaa-666', 'aaa-777'
        ],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'aaa-111').get()
    self.assertIsNone(alias_group)

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
        id='bbb-234',
        db_id='bbb-234',
        aliases=['bbb-123'],
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

  def test_split_alias_group(self):
    """Tests split an existing alias group into two.
    AliasGroup A -> B -> C -> D, remove the B -> C alias
    to get AliasGroups A -> B and C -> D."""
    osv.Bug(
        id='ddd-123',
        db_id='ddd-123',
        aliases=['ddd-124'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='ddd-124',
        db_id='ddd-124',
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='ddd-125',
        db_id='ddd-125',
        aliases=['ddd-126'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='ddd-126',
        db_id='ddd-126',
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['ddd-123', 'ddd-124', 'ddd-125', 'ddd-126'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'ddd-123').get()
    self.assertIsNotNone(alias_group)
    self.assertEqual(['ddd-123', 'ddd-124'], alias_group.bug_ids)
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'ddd-125').get()
    self.assertIsNotNone(alias_group)
    self.assertEqual(['ddd-125', 'ddd-126'], alias_group.bug_ids)

  def test_allow_list(self):
    """Test allow list."""
    osv.Bug(
        id='eee-111',
        db_id='eee-111',
        aliases=[
            'eee-222', 'eee-333', 'eee-444', 'eee-555', 'eee-666', 'eee-777'
        ],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasAllowListEntry(bug_id='eee-111',).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'eee-111').get()
    self.assertEqual(7, len(alias_group.bug_ids))

  def test_deny_list(self):
    """Tests deny list."""
    osv.Bug(
        id='fff-123',
        db_id='fff-123',
        aliases=['fff-124'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='fff-124',
        db_id='fff-124',
        aliases=['fff-125'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['fff-124', 'fff-125'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasDenyListEntry(bug_id='fff-123',).put()
    alias_computation.main()
    bug_ids = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'fff-124').get().bug_ids
    self.assertEqual(['fff-124', 'fff-125'], bug_ids)

  def test_merge_alias_group(self):
    """Tests all bugs of one alias group have been
    merged to other alias group."""
    osv.Bug(
        id='ggg-123',
        db_id='ggg-123',
        aliases=['ggg-124', 'ggg-125', 'ggg-126'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['ggg-123', 'ggg-124'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['ggg-125', 'ggg-126'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'ggg-125').fetch()
    self.assertEqual(1, len(alias_group))
    self.assertEqual(['ggg-123', 'ggg-124', 'ggg-125', 'ggg-126'],
                     alias_group[0].bug_ids)

  def test_partial_merge_alias_group(self):
    """Tests merging some bugs of one alias group to another alias group."""
    osv.Bug(
        id='hhh-123',
        db_id='hhh-123',
        aliases=['hhh-124', 'hhh-125'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.Bug(
        id='hhh-126',
        db_id='hhh-126',
        aliases=['hhh-127'],
        status=1,
        source='test',
        public=True,
        import_last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['hhh-123', 'hhh-124'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    osv.AliasGroup(
        bug_ids=['hhh-125', 'hhh-126', 'hhh-127'],
        last_modified=datetime.datetime(2023, 1, 1),
    ).put()
    alias_computation.main()
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'hhh-125').fetch()
    self.assertEqual(1, len(alias_group))
    self.assertEqual(['hhh-123', 'hhh-124', 'hhh-125'], alias_group[0].bug_ids)
    alias_group = osv.AliasGroup.query(
        osv.AliasGroup.bug_ids == 'hhh-127').fetch()
    self.assertEqual(1, len(alias_group))
    self.assertEqual(['hhh-126', 'hhh-127'], alias_group[0].bug_ids)


def test_alias_group_reaches_limit(self):
  """Tests a alias group reaches limit."""
  osv.Bug(
      id='iii-111',
      db_id='iii-111',
      aliases=[
          'iii-222',
          'iii-333',
          'iii-444',
          'iii-555',
          'iii-666',
          'iii-777',
          'iii-888',
          'iii-999',
          'iii-123',
          'iii-124',
          'iii-125',
          'iii-126',
          'iii-322',
          'iii-333',
          'iii-344',
          'iii-355',
      ],
      status=1,
      source='test',
      public=True,
      import_last_modified=datetime.datetime(2023, 1, 1),
  ).put()
  osv.AliasAllowListEntry(bug_id='iii-111',).put()
  alias_computation.main()
  alias_group = osv.AliasGroup.query(osv.AliasGroup.bug_ids == 'iii-111').get()
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
