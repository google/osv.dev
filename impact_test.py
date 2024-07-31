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
"""Impact tests."""

import codecs
import unittest

from . import impact
from . import tests
from . import models

from google.cloud import ndb


class UpdateAffectedCommitsTests(unittest.TestCase):
  """update_affected_commits tests."""

  def setUp(self):
    tests.reset_emulator()

  @classmethod
  def setUpClass(cls):
    cls._ds_emulator = tests.start_datastore_emulator()

    ndb_client = ndb.Client()
    cls._ndb_context = ndb_client.context()
    context = cls._ndb_context.__enter__()  # pylint: disable=unnecessary-dunder-call
    context.set_memcache_policy(False)
    context.set_cache_policy(False)

  @classmethod
  def tearDownClass(cls):
    tests.stop_emulator()
    cls._ndb_context.__exit__(None, None, None)  # pylint: disable=unnecessary-dunder-call

  def test_update_single_page(self):
    """Test update_affected_commits with a single page."""
    commits = {
        '00',
        '01',
        '02',
    }

    impact.update_affected_commits('BUG-1', commits, True)
    affected_commits = list(models.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertEqual('BUG-1-0', affected_commits.key.id())
    self.assertEqual('BUG-1', affected_commits.bug_id)
    self.assertEqual(0, affected_commits.page)
    self.assertTrue(affected_commits.public)

    self.assertCountEqual([
        b'00',
        b'01',
        b'02',
    ], [codecs.encode(commit, 'hex') for commit in affected_commits.commits])

  def test_update_single_page_nonpublic(self):
    """Test update_affected_commits with a single page."""
    commits = {
        '00',
        '01',
        '02',
    }

    impact.update_affected_commits('BUG-1', commits, False)
    affected_commits = list(models.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertEqual('BUG-1-0', affected_commits.key.id())
    self.assertEqual('BUG-1', affected_commits.bug_id)
    self.assertEqual(0, affected_commits.page)
    self.assertFalse(affected_commits.public)

    self.assertCountEqual([
        b'00',
        b'01',
        b'02',
    ], [codecs.encode(commit, 'hex') for commit in affected_commits.commits])

  def test_update_multiple_pages(self):
    """Test update_affected_commits with multiple page."""
    # These pre-populated pages should be deleted.
    for i in range(10):
      models.AffectedCommits(
          id=f'BUG-1-{i}', bug_id='BUG-1', commits=[], public=True,
          page=i).put()

    # These should not be deleted as they're for a different bug.
    models.AffectedCommits(
        id='BUG-2-0', bug_id='BUG-2', commits=[], public=True, page=0).put()

    commits = {'%08d' % number for number in range(26000)}

    impact.update_affected_commits('BUG-1', commits, True)
    affected_commits = list(models.AffectedCommits.query())
    self.assertEqual(4, len(affected_commits))

    # Check that the unrelated entry still exists.
    self.assertTrue(any(c.key.id() == 'BUG-2-0') for c in affected_commits)

    # Check that the new pages got written properly.
    affected_commits = list(
        models.AffectedCommits.query(models.AffectedCommits.bug_id == 'BUG-1'))

    for i, result in enumerate(affected_commits):
      self.assertEqual(f'BUG-1-{i}', result.key.id())
      self.assertEqual('BUG-1', result.bug_id)
      self.assertEqual(i, result.page)
      self.assertTrue(result.public)

    self.assertCountEqual(
        [b'%08d' % i for i in range(10000)],
        [codecs.encode(c, 'hex') for c in affected_commits[0].commits])
    self.assertCountEqual(
        [b'%08d' % i for i in range(10000, 20000)],
        [codecs.encode(c, 'hex') for c in affected_commits[1].commits])
    self.assertCountEqual(
        [b'%08d' % i for i in range(20000, 26000)],
        [codecs.encode(c, 'hex') for c in affected_commits[2].commits])

  def test_update_no_commits(self):
    """Test updates with no commits."""
    # These pre-populated pages should be deleted.
    for i in range(10):
      models.AffectedCommits(
          id=f'BUG-1-{i}', bug_id='BUG-1', commits=[], public=True,
          page=i).put()

    impact.update_affected_commits('BUG-1', set(), True)
    affected_commits = list(models.AffectedCommits.query())
    self.assertEqual(0, len(affected_commits))
