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
"""Worker tests."""
# pylint: disable=line-too-long
import datetime
import hashlib
import os
import shutil
import tempfile
import unittest
from unittest import mock

from google.cloud import ndb
import pygit2

import osv
from osv import tests
import oss_fuzz
import worker

TEST_BUCKET = 'test-osv-source-bucket'
TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')

ndb_client = None

# pylint: disable=protected-access,invalid-name


def _sha256(test_name):
  """Get sha256 sum."""
  hasher = hashlib.sha256()

  with open(os.path.join(TEST_DATA_DIR, test_name), 'rb') as f:
    hasher.update(f.read())

  return hasher.hexdigest()


class OssFuzzDetailsTest(unittest.TestCase):
  """Details generation tests."""

  def test_basic(self):
    """Basic tests."""
    crash_type = 'Heap-buffer-overflow'
    crash_state = 'Foo\nBar\nBlah\n'

    summary = oss_fuzz.get_oss_fuzz_summary(crash_type, crash_state)
    self.assertEqual('Heap-buffer-overflow in Foo', summary)

    details = oss_fuzz.get_oss_fuzz_details('1337', crash_type, crash_state)
    self.assertEqual(
        'OSS-Fuzz report: '
        'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1337\n\n'
        '```\n'
        'Crash type: Heap-buffer-overflow\n'
        'Crash state:\n'
        'Foo\n'
        'Bar\n'
        'Blah\n```\n', details)

  def test_no_issue(self):
    """Test generating details without an issue ID."""
    crash_type = 'Heap-buffer-overflow'
    crash_state = 'Foo\nBar\nBlah\n'

    details = oss_fuzz.get_oss_fuzz_details('', crash_type, crash_state)
    self.assertEqual(
        '```\n'
        'Crash type: Heap-buffer-overflow\n'
        'Crash state:\n'
        'Foo\n'
        'Bar\n'
        'Blah\n```\n', details)

  def test_assert(self):
    """Basic assertion failures."""
    crash_type = 'ASSERT'
    crash_state = 'idx < length\nFoo\nBar\n'

    summary = oss_fuzz.get_oss_fuzz_summary(crash_type, crash_state)
    self.assertEqual('ASSERT: idx < length', summary)

    details = oss_fuzz.get_oss_fuzz_details('1337', crash_type, crash_state)
    self.assertEqual(
        'OSS-Fuzz report: '
        'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1337\n\n'
        '```\n'
        'Crash type: ASSERT\n'
        'Crash state:\n'
        'idx < length\n'
        'Foo\n'
        'Bar\n```\n', details)

  def test_bad_cast(self):
    """Basic bad casts."""
    crash_type = 'Bad-cast'
    crash_state = 'Bad-cast to A from B\nFoo\nBar\n'

    summary = oss_fuzz.get_oss_fuzz_summary(crash_type, crash_state)
    self.assertEqual('Bad-cast to A from B', summary)

    details = oss_fuzz.get_oss_fuzz_details('1337', crash_type, crash_state)
    self.assertEqual(
        'OSS-Fuzz report: '
        'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1337\n\n'
        '```\n'
        'Crash type: Bad-cast\n'
        'Crash state:\n'
        'Bad-cast to A from B\n'
        'Foo\n'
        'Bar\n```\n', details)


class ImpactTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Impact task tests."""

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None

    tests.mock_clone(self, return_value=pygit2.Repository('osv-test'))
    tests.mock_datetime(self)

    osv.SourceRepository(id='oss-fuzz', name='oss-fuzz', db_prefix='OSV-').put()

    allocated_bug = osv.Bug(
        db_id='OSV-2020-1337',
        timestamp=datetime.datetime(2020, 1, 1),
        source_id='oss-fuzz:123',
        status=osv.BugStatus.UNPROCESSED,
        public=False)
    allocated_bug.put()

    should_be_deleted = osv.AffectedCommit(
        id='OSV-2020-1337-abcd',
        bug_id='OSV-2020-1337',
        commit='abcd',
        project='project',
        ecosystem='ecosystem',
        public=False)
    should_be_deleted.put()

  def test_basic(self):
    """Basic test."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': 'OSV-2020-1337',
    }

    regress_result = osv.RegressResult(
        id='oss-fuzz:123',
        commit='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        repo_url='https://repo.com/repo',
        issue_id='9001',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    regress_result.put()

    fix_result = osv.FixResult(
        id='oss-fuzz:123',
        commit='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        repo_url='https://repo.com/repo',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        details='DETAILS',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('basic',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
    ], [commit.commit for commit in affected_commits])

  def test_range(self):
    """Test commit range."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': 'OSV-2020-1337',
    }

    regress_result = osv.RegressResult(
        id='oss-fuzz:123',
        commit='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        repo_url='https://repo.com/repo',
        issue_id='9001',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    regress_result.put()

    fix_result = osv.FixResult(
        id='oss-fuzz:123',
        commit=('b1c95a196f22d06fcf80df8c6691cd113d8fefff:'
                '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2'),
        repo_url='https://repo.com/repo',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        details='DETAILS',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('range',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())

    self.assertCountEqual([
        'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
    ], [commit.commit for commit in affected_commits])

  def test_fixed_range_too_long(self):
    """Test fixed range that's too long."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': 'OSV-2020-1337',
    }

    regress_result = osv.RegressResult(
        id='oss-fuzz:123',
        commit='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        repo_url='https://repo.com/repo',
        issue_id='9001',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    regress_result.put()

    fix_result = osv.FixResult(
        id='oss-fuzz:123',
        commit=('eefe8ec3f1f90d0e684890e810f3f21e8500a4cd:'
                'b587c21c36a84e16cfc6b39eb68578d43b5281ad'),
        repo_url='https://repo.com/repo',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        details='DETAILS',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('fixed_range_too_long',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())

    self.assertCountEqual([
        'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        '3ea6feea9bb853596c727abab309476cc07d1505',
        '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2',
    ], [commit.commit for commit in affected_commits])

  def test_zero_regression_range(self):
    """Test regression range with "0:X"."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': 'OSV-2020-1337',
    }

    regress_result = osv.RegressResult(
        id='oss-fuzz:123',
        commit='unknown:eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        repo_url='https://repo.com/repo',
        issue_id='9001',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    regress_result.put()

    fix_result = osv.FixResult(
        id='oss-fuzz:123',
        commit='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        repo_url='https://repo.com/repo',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        details='DETAILS',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('zero_regression_range',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())

    self.assertCountEqual([
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
    ], [commit.commit for commit in affected_commits])

  def test_simplify_range(self):
    """Test simplifying commit range."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': 'OSV-2020-1337',
    }

    regress_result = osv.RegressResult(
        id='oss-fuzz:123',
        commit=('a2ba949290915d445d34d0e8e9de2e7ce38198fc:'
                'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd'),
        repo_url='https://repo.com/repo',
        issue_id='9001',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    regress_result.put()

    fix_result = osv.FixResult(
        id='oss-fuzz:123',
        commit=('b1c95a196f22d06fcf80df8c6691cd113d8fefff:'
                '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735'),
        repo_url='https://repo.com/repo',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        details='DETAILS',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('simplify_range',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

  def test_not_fixed(self):
    """Test not fixed bug."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': 'OSV-2020-1337',
    }

    regress_result = osv.RegressResult(
        id='oss-fuzz:123',
        commit='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        repo_url='https://repo.com/repo',
        issue_id='9001',
        project='project',
        ecosystem='ecosystem',
        summary='Heap-buffer-overflow in Foo',
        details='DETAILS',
        severity='MEDIUM',
        reference_urls=['https://url/'])
    regress_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('not_fixed',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2',
        '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
        'b587c21c36a84e16cfc6b39eb68578d43b5281ad',
        '88e5ae3c40c85b702ba89a34c29f233048abb12b',
        '3ea6feea9bb853596c727abab309476cc07d1505',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
    ], [commit.commit for commit in affected_commits])


class EcosystemTest(unittest.TestCase):
  """Test getting ecosystem."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    self.oss_fuzz_checkout = os.path.join(self.tmp_dir, 'oss-fuzz')
    osv.ensure_updated_checkout(worker.OSS_FUZZ_GIT_URL, self.oss_fuzz_checkout)

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_get_ecosystem(self):
    """Test getting ecosystems."""
    self.assertEqual('PyPI',
                     oss_fuzz.get_ecosystem(self.oss_fuzz_checkout, 'pillow'))
    self.assertEqual(
        'Go', oss_fuzz.get_ecosystem(self.oss_fuzz_checkout, 'golang-protobuf'))
    self.assertEqual('OSS-Fuzz',
                     oss_fuzz.get_ecosystem(self.oss_fuzz_checkout, 'openssl'))


class MarkBugInvalidTest(unittest.TestCase):
  """Test mark_bug_invalid."""

  def setUp(self):
    tests.reset_emulator()

  def test_mark_bug_invalid(self):
    """Test mark_bug_invalid."""
    osv.SourceRepository(id='oss-fuzz', name='oss-fuzz', db_prefix='OSV-').put()
    osv.Bug(db_id='OSV-2021-1', source_id='oss-fuzz:1337').put()
    osv.AffectedCommit(bug_id='OSV-2021-1').put()
    osv.AffectedCommit(bug_id='OSV-2021-1').put()

    message = mock.Mock()
    message.attributes = {
        'type': 'invalid',
        'testcase_id': '1337',
        'source_id': '',
    }

    worker.mark_bug_invalid(message)
    bug = ndb.Key(osv.Bug, 'OSV-2021-1').get()
    self.assertEqual(osv.BugStatus.INVALID, bug.status)

    commits = list(osv.AffectedCommit.query())
    self.assertEqual(0, len(commits))


class FindOssFuzzFixViaCommitTest(unittest.TestCase):
  """Test finding OSS-Fuzz fixes via commits."""

  def setUp(self):
    self.repo = pygit2.Repository('osv-test')

  def test_has_issue_id(self):
    """Test identifying the commit that has the issue ID."""
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '949f182716f037e25394bbb98d39b3295d230a29', 'oss-fuzz:133713371337',
        '12345')
    self.assertEqual('57e58a5d7c2bb3ce0f04f17ec0648b92ee82531f', commit)

    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '25147a74d8aeb27b43665530ee121a2a1b19dc58', 'oss-fuzz:133713371337',
        '12345')
    self.assertEqual('25147a74d8aeb27b43665530ee121a2a1b19dc58', commit)

  def test_has_testcase_id(self):
    """Test identifying the commit that has the testcase ID."""
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '00514d6f244f696e750a37083163992c6a50cfd3', 'oss-fuzz:133713371337',
        '12345')

    self.assertEqual('90aa4127295b2c37b5f7fcf6a9772b12c99a5212', commit)

  def test_has_oss_fuzz_reference(self):
    """Test identifying the commit that has the testcase ID."""
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        'b1fa81a5d59e9b4d6e276d82fc17058f3cf139d9', 'oss-fuzz:133713371337',
        '12345')

    self.assertEqual('3c5dcf6a5bec14baab3b247d369a7270232e1b83', commit)

  def test_has_multiple_oss_fuzz_reference(self):
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '949f182716f037e25394bbb98d39b3295d230a29', 'oss-fuzz:7331', '54321')
    self.assertIsNone(commit)


class UpdateTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Vulnerability update tests."""

  def mock_clone(self, repo_url, *args, **kwargs):
    if 'osv-test' in repo_url:
      return pygit2.Repository('osv-test')

    return self.original_clone(repo_url, *args, **kwargs)

  def _load_test_data(self, name):
    """Load test data."""
    with open(os.path.join(TEST_DATA_DIR, name)) as f:
      return f.read()

  def setUp(self):
    self.maxDiff = None
    tests.reset_emulator()

    self.original_clone = osv.clone
    tests.mock_clone(self, func=self.mock_clone)

    tests.mock_datetime(self)

    # Initialise fake source_repo.
    self.tmp_dir = tempfile.TemporaryDirectory()

    self.mock_repo = tests.mock_repository(self)
    self.remote_source_repo_path = self.mock_repo.path
    self.mock_repo.add_file(
        'BLAH-123.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'BLAH-123.yaml')))
    self.mock_repo.add_file(
        'BLAH-124.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'BLAH-124.yaml')))
    self.mock_repo.add_file(
        'BLAH-125.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'BLAH-125.yaml')))
    self.mock_repo.add_file(
        'BLAH-127.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'BLAH-127.yaml')))
    self.mock_repo.add_file(
        'BLAH-128.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'BLAH-128.yaml')))
    self.mock_repo.commit('User', 'user@email')

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.GIT,
        id='source',
        name='source',
        db_prefix='BLAH-',
        repo_url='file://' + self.remote_source_repo_path,
        editable=True,
        repo_username='')
    self.source_repo.put()

    osv.Bug(
        db_id='BLAH-123',
        project=['blah.com/package'],
        ecosystem=['golang'],
        source_id='source:BLAH-123.yaml',
        import_last_modified=datetime.datetime(2021, 1, 1, 0, 0),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()
    osv.Bug(
        db_id='BLAH-124',
        regressed='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        project=['blah.com/package'],
        ecosystem=['golang'],
        source_id='source:BLAH-124.yaml',
        import_last_modified=datetime.datetime(2021, 1, 1, 0, 0),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()
    osv.Bug(
        db_id='BLAH-125',
        regressed='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        fixed='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        project=['blah.com/package'],
        ecosystem=['golang'],
        source_id='source:BLAH-125.yaml',
        import_last_modified=datetime.datetime(2021, 1, 1, 0, 0),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()
    osv.Bug(
        db_id='BLAH-127',
        project=['blah.com/package'],
        ecosystem=['golang'],
        source_id='source:BLAH-127.yaml',
        import_last_modified=datetime.datetime(2021, 1, 1, 0, 0),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()

    mock_publish = mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
    self.mock_publish = mock_publish.start()
    self.addCleanup(mock_publish.stop)

  def tearDown(self):
    self.tmp_dir.cleanup()

  def test_update(self):
    """Test basic update."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-123.yaml',
        'original_sha256': _sha256('BLAH-123.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-123', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_update', diff.patch)
    self.expect_dict_equal('update', osv.Bug.get_by_id('BLAH-123')._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
    ], [commit.commit for commit in affected_commits])

    self.mock_publish.assert_not_called()

  def test_update_limit(self):
    """Test basic update with limit events."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-128.yaml',
        'original_sha256': _sha256('BLAH-128.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-128', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_update_limit', diff.patch)
    self.expect_dict_equal('update_limit',
                           osv.Bug.get_by_id('BLAH-128')._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        'a2ba949290915d445d34d0e8e9de2e7ce38198fc',
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
    ], [commit.commit for commit in affected_commits])

  def test_update_add_fix(self):
    """Test basic update adding a fix."""
    fix_result = osv.FixResult(
        id='source:BLAH-124.yaml',
        repo_url='https://osv-test/repo/url',
        commit='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735')
    fix_result.put()
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-124.yaml',
        'original_sha256': _sha256('BLAH-124.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-124', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_update_add_fix', diff.patch)
    self.expect_dict_equal('update_add_fix',
                           osv.Bug.get_by_id('BLAH-124')._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
    ], [commit.commit for commit in affected_commits])

  def test_update_no_introduced(self):
    """Test update vulnerability with no introduced commit."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-127.yaml',
        'original_sha256': _sha256('BLAH-127.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-127', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_dict_equal('update_no_introduced',
                           osv.Bug.get_by_id('BLAH-127')._to_dict())
    self.expect_equal('diff_update_no_introduced', diff.patch)

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        'a2ba949290915d445d34d0e8e9de2e7ce38198fc',
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '00514d6f244f696e750a37083163992c6a50cfd3',
        '25147a74d8aeb27b43665530ee121a2a1b19dc58',
        '3c5dcf6a5bec14baab3b247d369a7270232e1b83',
        '4c155795426727ea05575bd5904321def23c03f4',
        '57e58a5d7c2bb3ce0f04f17ec0648b92ee82531f',
        '90aa4127295b2c37b5f7fcf6a9772b12c99a5212',
        '949f182716f037e25394bbb98d39b3295d230a29',
        'b1fa81a5d59e9b4d6e276d82fc17058f3cf139d9',
        'f0cc40d8c3dabb27c2cfe26f1764305abc91a0b9',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
    ], [commit.commit for commit in affected_commits])

  def test_update_new(self):
    """Test update with new vulnerability added."""
    self.mock_repo.add_file(
        'BLAH-126.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'BLAH-126.yaml')))
    self.mock_repo.commit('User', 'user@email')

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-126.yaml',
        'original_sha256': _sha256('BLAH-126.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-126', commit.message)

    self.expect_dict_equal('update_new',
                           osv.Bug.get_by_id('BLAH-126')._to_dict())

  def test_update_delete(self):
    """Test deletion."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    self.mock_repo.delete_file('BLAH-123.yaml')
    self.mock_repo.commit('User', 'user@email')

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-123.yaml',
        'original_sha256': _sha256('BLAH-123.yaml'),
        'deleted': 'true',
    }
    task_runner._source_update(message)
    bug = osv.Bug.get_by_id('BLAH-123')
    self.assertEqual(osv.BugStatus.INVALID, bug.status)

  def test_update_no_changes(self):
    """Test basic update (with no changes)."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-125.yaml',
        'original_sha256': _sha256('BLAH-125.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('user@email', commit.author.email)
    self.assertEqual('User', commit.author.name)

  def test_update_conflict(self):
    """Test basic update with a conflict."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-123.yaml',
        'original_sha256': 'invalid',
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    # Latest commit is still the user commit.
    self.assertEqual('user@email', commit.author.email)
    self.assertEqual('User', commit.author.name)

  def test_update_conflict_while_pushing(self):
    """Test basic update with a conflict while pushing."""
    original_push_source_changes = osv.push_source_changes

    def mock_push_source_changes(*args, **kwargs):
      self.mock_repo.add_file('BLAH-123.yaml', 'changed')
      self.mock_repo.commit('Another user', 'user@email')

      original_push_source_changes(*args, **kwargs)

    patcher = mock.patch('osv.push_source_changes')
    self.addCleanup(patcher.stop)
    patcher.start().side_effect = mock_push_source_changes

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-123.yaml',
        'original_sha256': _sha256('BLAH-123.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    # Latest commit is still the user commit.
    self.assertEqual('user@email', commit.author.email)
    self.assertEqual('Another user', commit.author.name)

  def test_update_pypi(self):
    """Test a PyPI entry."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.put()

    self.mock_repo.add_file(
        'PYSEC-123.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'PYSEC-123.yaml')))
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'PYSEC-123.yaml',
        'original_sha256': _sha256('PYSEC-123.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update PYSEC-123', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.expect_equal('diff_pypi', diff.patch)

    self.expect_dict_equal(
        'update_pypi',
        ndb.Key(osv.Bug, 'source:PYSEC-123').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
    ], [a.commit for a in affected_commits])

    self.expect_equal('pypi_pubsub_calls', self.mock_publish.mock_calls)

  def test_normalize_pypi(self):
    """Test a PyPI entry normalizes as expected."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.put()

    self.mock_repo.add_file(
        'PYSEC-456.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'PYSEC-456.yaml')))
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'PYSEC-456.yaml',
        'original_sha256': _sha256('PYSEC-456.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_normalized_pypi', diff.patch)

    self.expect_dict_equal(
        'normalized_pypi',
        ndb.Key(osv.Bug, 'source:PYSEC-456').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
    ], [a.commit for a in affected_commits])

    self.expect_equal('normalized_pypi_pubsub_calls',
                      self.mock_publish.mock_calls)

  def test_update_last_affected(self):
    """Test a PyPI entry."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.put()

    self.mock_repo.add_file(
        'PYSEC-124.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'PYSEC-124.yaml')))
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'PYSEC-124.yaml',
        'original_sha256': _sha256('PYSEC-124.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update PYSEC-124', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.expect_equal('diff_last_affected', diff.patch)

    self.expect_dict_equal(
        'update_last_affected',
        ndb.Key(osv.Bug, 'source:PYSEC-124').get()._to_dict())

  def test_update_maven(self):
    """Test updating maven."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.put()

    self.mock_repo.add_file(
        'GHSA-838r-hvwh-24h8.json',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'GHSA-838r-hvwh-24h8.json')))
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'GHSA-838r-hvwh-24h8.json',
        'original_sha256': _sha256('GHSA-838r-hvwh-24h8.json'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update GHSA-838r-hvwh-24h8', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.expect_equal('diff_maven', diff.patch)

    self.expect_dict_equal(
        'update_maven',
        ndb.Key(osv.Bug, 'source:GHSA-838r-hvwh-24h8').get()._to_dict())

    self.mock_publish.assert_not_called()

  def test_update_bucket(self):
    """Test bucket entries."""
    self.source_repo.type = osv.SourceRepositoryType.BUCKET
    self.source_repo.bucket = TEST_BUCKET
    self.source_repo.editable = False
    self.source_repo.put()

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'a/b/test.json',
        'original_sha256': ('b2b37bde8f39256239419078de672ce7'
                            'a408735f1c2502ee8fa08745096e1971'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('update_bucket_0',
                           osv.Bug.get_by_id('GO-2021-0085')._to_dict())
    self.expect_dict_equal('update_bucket_1',
                           osv.Bug.get_by_id('GO-2021-0087')._to_dict())

  def test_update_debian(self):
    """Test updating debian."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.put()

    self.mock_repo.add_file(
        'DSA-3029-1.json',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'DSA-3029-1.json')))
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'DSA-3029-1.json',
        'original_sha256': _sha256('DSA-3029-1.json'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update DSA-3029-1', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_debian', diff.patch)

    self.expect_dict_equal(
        'update_debian',
        ndb.Key(osv.Bug, 'source:DSA-3029-1').get()._to_dict())

    self.mock_publish.assert_not_called()

  def test_update_android(self):
    """Test updating Android through bucket entries."""
    self.source_repo.type = osv.SourceRepositoryType.BUCKET
    self.source_repo.bucket = TEST_BUCKET
    self.source_repo.editable = False
    self.source_repo.put()

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'a/b/android-test.json',
        'original_sha256': ('12453f85cd87bc1d465e0d013db572c0'
                            '1f7fb7de3b3a33de94ebcc7bd0f23a14'),
        'deleted': 'false',
    }

    task_runner._source_update(message)
    self.expect_dict_equal('update_bucket_2',
                           osv.Bug.get_by_id('ASB-A-153358911')._to_dict())


if __name__ == '__main__':
  os.system('pkill -f datastore')
  ds_emulator = tests.start_datastore_emulator()
  try:
    ndb_client = ndb.Client()
    with ndb_client.context() as context:
      context.set_memcache_policy(False)
      context.set_cache_policy(False)
      unittest.main()
  finally:
    # TODO(ochang): Cleaner way of properly cleaning up processes.
    os.system('pkill -f datastore')
