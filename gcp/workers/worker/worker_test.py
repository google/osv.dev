# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the 'License');
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an 'AS IS' BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Worker tests."""
# pylint: disable=line-too-long
import codecs
import datetime
import hashlib
from gcp.workers.mock_test.mock_test_handler import MockDataHandler
import http.server
import os
import shutil
import tempfile
import threading
import warnings
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
PORT = 8000
SERVER_ADDRESS = ('localhost', PORT)
MOCK_ADDRESS_FORMAT = f'http://{SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}/'
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
        'Blah\n```\n',
        details,
    )

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
        'Blah\n```\n',
        details,
    )

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
        'Bar\n```\n',
        details,
    )

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
        'Bar\n```\n',
        details,
    )


class ImpactTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Impact task tests."""

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None

    tests.mock_clone(self, return_value=pygit2.Repository('osv-test'))
    tests.mock_datetime(self)

    osv.SourceRepository(
        id='oss-fuzz', name='oss-fuzz', db_prefix=['OSV-']).put()

    allocated_bug = osv.Bug(
        db_id='OSV-2020-1337',
        timestamp=datetime.datetime(2020, 1, 1, tzinfo=datetime.UTC),
        source_id='oss-fuzz:123',
        status=osv.BugStatus.UNPROCESSED,
        public=False,
    )
    allocated_bug.put()

    # This should be deleted and overwritten with the actual computed commits.
    osv.AffectedCommits(
        id='OSV-2020-1337-3', bug_id='OSV-2020-1337', page=3).put()

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
        reference_urls=['https://url/'],
    )
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
        reference_urls=['https://url/'],
    )
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('basic',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

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
        reference_urls=['https://url/'],
    )
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
        reference_urls=['https://url/'],
    )
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal('range',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

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
        reference_urls=['https://url/'],
    )
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
        reference_urls=['https://url/'],
    )
    fix_result.put()

    with self.assertLogs(level='WARNING') as logs:
      oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.assertEqual(logs.output,
                     ['WARNING:root:Too many commits in fix range.'])

    self.expect_dict_equal(
        'fixed_range_too_long',
        ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict(),
    )

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2',
            b'3ea6feea9bb853596c727abab309476cc07d1505',
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

  def test_zero_regression_range(self):
    """Test regression range with '0:X'."""
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
        reference_urls=['https://url/'],
    )
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
        reference_urls=['https://url/'],
    )
    fix_result.put()

    oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.expect_dict_equal(
        'zero_regression_range',
        ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict(),
    )

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

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
        reference_urls=['https://url/'],
    )
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
        reference_urls=['https://url/'],
    )
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
        reference_urls=['https://url/'],
    )
    regress_result.put()

    with self.assertLogs(level='WARNING') as logs:
      oss_fuzz.process_impact_task('oss-fuzz:123', message)
    self.assertEqual(logs.output,
                     ['WARNING:root:Missing FixResult for oss-fuzz:123'])

    self.expect_dict_equal('not_fixed',
                           ndb.Key(osv.Bug, 'OSV-2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2',
            b'3ea6feea9bb853596c727abab309476cc07d1505',
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'88e5ae3c40c85b702ba89a34c29f233048abb12b',
            b'8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'b587c21c36a84e16cfc6b39eb68578d43b5281ad',
            b'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )


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
        'Go',
        oss_fuzz.get_ecosystem(self.oss_fuzz_checkout, 'golang-protobuf'),
    )
    self.assertEqual(
        'OSS-Fuzz',
        oss_fuzz.get_ecosystem(self.oss_fuzz_checkout, 'openssl'),
    )


class MarkBugInvalidTest(unittest.TestCase):
  """Test mark_bug_invalid."""

  def setUp(self):
    tests.reset_emulator()

  def test_mark_bug_invalid(self):
    """Test mark_bug_invalid."""
    osv.SourceRepository(
        id='oss-fuzz', name='oss-fuzz', db_prefix=['OSV-']).put()
    osv.Bug(db_id='OSV-2021-1', source_id='oss-fuzz:1337').put()
    osv.AffectedCommits(bug_id='OSV-2021-1').put()
    osv.AffectedCommits(bug_id='OSV-2021-1').put()

    message = mock.Mock()
    message.attributes = {
        'type': 'invalid',
        'testcase_id': '1337',
        'source_id': '',
    }

    worker.mark_bug_invalid(message)
    bug = ndb.Key(osv.Bug, 'OSV-2021-1').get()
    self.assertEqual(osv.BugStatus.INVALID, bug.status)

    commits = list(osv.AffectedCommits.query())
    self.assertEqual(0, len(commits))


class FindOssFuzzFixViaCommitTest(unittest.TestCase):
  """Test finding OSS-Fuzz fixes via commits."""

  def setUp(self):
    self.repo = pygit2.Repository('osv-test')

  def test_has_issue_id(self):
    """Test identifying the commit that has the issue ID."""
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo,
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '949f182716f037e25394bbb98d39b3295d230a29',
        'oss-fuzz:133713371337',
        '12345',
    )
    self.assertEqual('57e58a5d7c2bb3ce0f04f17ec0648b92ee82531f', commit)

    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo,
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '25147a74d8aeb27b43665530ee121a2a1b19dc58',
        'oss-fuzz:133713371337',
        '12345',
    )
    self.assertEqual('25147a74d8aeb27b43665530ee121a2a1b19dc58', commit)

  def test_has_testcase_id(self):
    """Test identifying the commit that has the testcase ID."""
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo,
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '00514d6f244f696e750a37083163992c6a50cfd3',
        'oss-fuzz:133713371337',
        '12345',
    )

    self.assertEqual('90aa4127295b2c37b5f7fcf6a9772b12c99a5212', commit)

  def test_has_oss_fuzz_reference(self):
    """Test identifying the commit that has the testcase ID."""
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo,
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        'b1fa81a5d59e9b4d6e276d82fc17058f3cf139d9',
        'oss-fuzz:133713371337',
        '12345',
    )

    self.assertEqual('3c5dcf6a5bec14baab3b247d369a7270232e1b83', commit)

  def test_has_multiple_oss_fuzz_reference(self):
    commit = oss_fuzz.find_oss_fuzz_fix_via_commit(
        self.repo,
        'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '949f182716f037e25394bbb98d39b3295d230a29',
        'oss-fuzz:7331',
        '54321',
    )
    self.assertIsNone(commit)


class RESTUpdateTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Vulnerability update tests."""

  def setUp(self):
    self.maxDiff = None
    tests.reset_emulator()
    tests.mock_datetime(self)

    # Initialise fake source_repo.
    self.tmp_dir = tempfile.TemporaryDirectory()

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.REST_ENDPOINT,
        id='source',
        name='source',
        rest_api_url=MOCK_ADDRESS_FORMAT,
        link=MOCK_ADDRESS_FORMAT,
        editable=False,
        repo_username='',
        extension='.json',
        ignore_git=True,
    )
    self.source_repo.put()
    osv.ecosystems.config.work_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'testdata/tmp/')

    mock_publish = mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
    self.mock_publish = mock_publish.start()
    self.addCleanup(mock_publish.stop)
    warnings.filterwarnings('ignore', 'unclosed', ResourceWarning)
    self.httpd = http.server.HTTPServer(SERVER_ADDRESS, MockDataHandler)
    thread = threading.Thread(target=self.httpd.serve_forever)
    thread.start()

  def tearDown(self):
    self.httpd.shutdown()
    self.tmp_dir.cleanup()

  def test_update(self):
    """Test updating rest."""
    solo_endpoint = 'CURL-CVE-2022-32221' + '.json'
    sha = '6138604b5537caab2afc0ee3e2b11f1574fdd5d8f3c6173f64048341cf55aee4'
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': solo_endpoint,
        'original_sha256': sha,
        'deleted': 'false',
    }
    task_runner._source_update(message)
    self.mock_publish.assert_not_called()

  def test_git_ranges(self):
    """Test updating rest."""
    solo_endpoint = 'CURL-CVE-2022-32221' + '.json'
    sha = '6138604b5537caab2afc0ee3e2b11f1574fdd5d8f3c6173f64048341cf55aee4'
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    osv.Bug(
        db_id='CURL-CVE-2022-32221',
        ecosystem=[''],
        source_id='source:CURL-CVE-2022-32221.json',
        import_last_modified=datetime.datetime(
            2020, 1, 1, 0, 0, tzinfo=datetime.UTC),
    ).put()
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': solo_endpoint,
        'original_sha256': sha,
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('update_no_introduced',
                           osv.Bug.get_by_id('CURL-CVE-2022-32221')._to_dict())

  def test_update_redhat_toobig(self):
    """Test failure handling of a too-large Red Hat record."""
    solo_endpoint = 'RHSA-2018:3140' + '.json'
    sha = 'a5cc068278ddad5f4c63d9b4f27baf59f296076306a24e850c5edde1b0232b0c'

    self.source_repo.db_prefix.append('RHSA-')
    self.source_repo.put()

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': solo_endpoint,
        'original_sha256': sha,
        'deleted': 'false',
    }
    with self.assertLogs(level='ERROR') as logs:
      task_runner._source_update(message)

    self.assertIn(
        "ERROR:root:Unexpected exception while writing RHSA-2018:3140 to Datastore",
        logs.output[0])

    self.mock_publish.assert_not_called()


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
        'OSV-123.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-123.yaml')),
    )
    self.mock_repo.add_file(
        'OSV-124.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-124.yaml')),
    )
    self.mock_repo.add_file(
        'OSV-125.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-125.yaml')),
    )
    self.mock_repo.add_file(
        'OSV-127.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-127.yaml')),
    )
    self.mock_repo.add_file(
        'OSV-128.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-128.yaml')),
    )
    self.mock_repo.add_file(
        'OSV-131.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-131.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.GIT,
        id='source',
        name='source',
        db_prefix=['OSV-'],
        repo_url='file://' + self.remote_source_repo_path,
        editable=True,
        repo_username='',
    )
    self.source_repo.put()

    osv.Bug(
        db_id='OSV-123',
        project=['blah.com/package'],
        ecosystem=['Go'],
        source_id='source:OSV-123.yaml',
        import_last_modified=datetime.datetime(
            2021, 1, 1, 0, 0, tzinfo=datetime.UTC),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
    ).put()
    osv.Bug(
        db_id='OSV-124',
        regressed='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        project=['blah.com/package'],
        ecosystem=['Go'],
        source_id='source:OSV-124.yaml',
        import_last_modified=datetime.datetime(
            2021, 1, 1, 0, 0, tzinfo=datetime.UTC),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
    ).put()
    osv.Bug(
        db_id='OSV-125',
        regressed='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        fixed='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        project=['blah.com/package'],
        ecosystem=['Go'],
        source_id='source:OSV-125.yaml',
        import_last_modified=datetime.datetime(
            2021, 1, 1, 0, 0, tzinfo=datetime.UTC),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
    ).put()
    osv.Bug(
        db_id='OSV-127',
        project=['blah.com/package'],
        ecosystem=['Go'],
        source_id='source:OSV-127.yaml',
        import_last_modified=datetime.datetime(
            2021, 1, 1, 0, 0, tzinfo=datetime.UTC),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
    ).put()
    osv.Bug(
        db_id='OSV-131',
        project=['blah.com/package'],
        ecosystem=['ecosystem'],
        source_id='source:OSV-131.yaml',
        import_last_modified=datetime.datetime(
            2021, 1, 1, 0, 0, tzinfo=datetime.UTC),
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
    ).put()

    mock_publish = mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
    self.mock_publish = mock_publish.start()
    self.addCleanup(mock_publish.stop)

    osv.ecosystems.config.work_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'testdata/tmp/')

    # Add fake ecosystems used in tests to supported ecosystems.
    osv.ecosystems._ecosystems._ecosystems.update({
        'ecosystem': osv.ecosystems.OrderingUnsupportedEcosystem(),
    })

  def tearDown(self):
    self.tmp_dir.cleanup()

  def test_update(self):
    """Test basic update."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-123.yaml',
        'original_sha256': _sha256('OSV-123.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update OSV-123', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_update', diff.patch)
    self.expect_dict_equal('update', osv.Bug.get_by_id('OSV-123')._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

    self.mock_publish.assert_not_called()

  def test_update_limit(self):
    """Test basic update with limit events."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-128.yaml',
        'original_sha256': _sha256('OSV-128.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update OSV-128', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_update_limit', diff.patch)
    self.expect_dict_equal('update_limit',
                           osv.Bug.get_by_id('OSV-128')._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'a2ba949290915d445d34d0e8e9de2e7ce38198fc',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

  def test_update_add_fix(self):
    """Test basic update adding a fix."""
    fix_result = osv.FixResult(
        id='source:OSV-124.yaml',
        repo_url='https://osv-test/repo/url',
        commit='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
    )
    fix_result.put()
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-124.yaml',
        'original_sha256': _sha256('OSV-124.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update OSV-124', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_update_add_fix', diff.patch)
    self.expect_dict_equal('update_add_fix',
                           osv.Bug.get_by_id('OSV-124')._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

  def test_update_no_introduced(self):
    """Test update vulnerability with no introduced commit."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-127.yaml',
        'original_sha256': _sha256('OSV-127.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update OSV-127', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_dict_equal('update_no_introduced',
                           osv.Bug.get_by_id('OSV-127')._to_dict())
    self.expect_equal('diff_update_no_introduced', diff.patch)

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'00514d6f244f696e750a37083163992c6a50cfd3',
            b'25147a74d8aeb27b43665530ee121a2a1b19dc58',
            b'3c5dcf6a5bec14baab3b247d369a7270232e1b83',
            b'4c155795426727ea05575bd5904321def23c03f4',
            b'57e58a5d7c2bb3ce0f04f17ec0648b92ee82531f',
            b'90aa4127295b2c37b5f7fcf6a9772b12c99a5212',
            b'949f182716f037e25394bbb98d39b3295d230a29',
            b'a2ba949290915d445d34d0e8e9de2e7ce38198fc',
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'b1fa81a5d59e9b4d6e276d82fc17058f3cf139d9',
            b'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'f0cc40d8c3dabb27c2cfe26f1764305abc91a0b9',
            b'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
            b'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

  def test_update_new(self):
    """Test update with new vulnerability added."""
    self.mock_repo.add_file(
        'OSV-126.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-126.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-126.yaml',
        'original_sha256': _sha256('OSV-126.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update OSV-126', commit.message)

    self.expect_dict_equal('update_new',
                           osv.Bug.get_by_id('OSV-126')._to_dict())

  def test_update_delete(self):
    """Test deletion."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    self.mock_repo.delete_file('OSV-123.yaml')
    self.mock_repo.commit('User', 'user@email')

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-123.yaml',
        'original_sha256': _sha256('OSV-123.yaml'),
        'deleted': 'true',
    }
    task_runner._source_update(message)
    bug = osv.Bug.get_by_id('OSV-123')
    self.assertEqual(osv.BugStatus.INVALID, bug.status)

  def test_update_no_changes(self):
    """Test basic update (with no changes)."""
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-125.yaml',
        'original_sha256': _sha256('OSV-125.yaml'),
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
        'path': 'OSV-123.yaml',
        'original_sha256': 'invalid',
        'deleted': 'false',
    }

    with self.assertLogs(level='WARNING') as logs:
      task_runner._source_update(message)
    self.assertEqual(
        logs.output,
        [
            f'WARNING:root:sha256sum of OSV-123.yaml no longer matches (expected=invalid vs current={_sha256("OSV-123.yaml")}).'
        ],
    )

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    # Latest commit is still the user commit.
    self.assertEqual('user@email', commit.author.email)
    self.assertEqual('User', commit.author.name)

  def test_update_conflict_while_pushing(self):
    """Test basic update with a conflict while pushing."""
    original_push_source_changes = osv.push_source_changes

    def mock_push_source_changes(*args, **kwargs):
      self.mock_repo.add_file('OSV-123.yaml', 'changed')
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
        'path': 'OSV-123.yaml',
        'original_sha256': _sha256('OSV-123.yaml'),
        'deleted': 'false',
    }

    with self.assertLogs(level='WARNING') as logs:
      task_runner._source_update(message)

    self.assertEqual(len(logs.output), 3)
    self.assertEqual(
        logs.output[0],
        'WARNING:root:Failed to push: cannot push because a reference that you are trying to update on the remote contains commits that are not present locally.',
    )
    self.assertRegex(
        logs.output[1],
        r'WARNING:root:Upstream hash for .*/OSV-123.yaml changed \(expected=.* vs current=.*\)',
    )
    self.assertEqual(
        logs.output[2],
        'WARNING:root:Discarding changes for OSV-123 due to conflicts.',
    )

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
    self.source_repo.db_prefix.append('PYSEC-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'PYSEC-123.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'PYSEC-123.yaml')),
    )
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

    self.expect_dict_equal('update_pypi',
                           ndb.Key(osv.Bug, 'PYSEC-123').get()._to_dict())

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

    self.expect_equal('pypi_pubsub_calls', self.mock_publish.mock_calls)

  def test_normalize_pypi(self):
    """Test a PyPI entry normalizes as expected."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('PYSEC-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'PYSEC-456.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'PYSEC-456.yaml')),
    )
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
        ndb.Key(osv.Bug, 'PYSEC-456').get()._to_dict(),
    )

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

    self.expect_equal('normalized_pypi_pubsub_calls',
                      self.mock_publish.mock_calls)

  def test_update_last_affected(self):
    """Test a PyPI entry."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('PYSEC-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'PYSEC-124.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'PYSEC-124.yaml')),
    )
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
        ndb.Key(osv.Bug, 'PYSEC-124').get()._to_dict(),
    )

  def test_update_maven(self):
    """Test updating maven."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('GHSA-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'GHSA-838r-hvwh-24h8.json',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'GHSA-838r-hvwh-24h8.json')),
    )
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
        ndb.Key(osv.Bug, 'GHSA-838r-hvwh-24h8').get()._to_dict(),
    )

    self.mock_publish.assert_not_called()

  def test_update_linux(self):
    """Test a Linux entry."""
    self.skipTest("Prefix not supported by schema")
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('LINUX-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'LINUX-123.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'LINUX-123.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'LINUX-123.yaml',
        'original_sha256': _sha256('LINUX-123.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal(
        'update_linux',
        ndb.Key(osv.Bug, 'LINUX-123').get()._to_dict(),
    )

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

  def test_update_bucket(self):
    """Test bucket entries."""
    self.source_repo.type = osv.SourceRepositoryType.BUCKET
    self.source_repo.bucket = TEST_BUCKET
    self.source_repo.editable = False
    self.source_repo.db_prefix.append('GO-')
    self.source_repo.put()

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'a/b/test.json',
        'original_sha256': ('62966a80f6f9f54161803211069216177'
                            '37340a47f43356ee4a1cabe8f089869'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('update_bucket_0',
                           osv.Bug.get_by_id('GO-2021-0085')._to_dict())

  def test_update_debian(self):
    """Test updating debian."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('DSA-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'DSA-3029-1.json',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'DSA-3029-1.json')),
    )
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
        ndb.Key(osv.Bug, 'DSA-3029-1').get()._to_dict(),
    )

    self.mock_publish.assert_not_called()

  def test_update_alpine(self):
    """Test updating alpine."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('CVE-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'CVE-2022-27449.json',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'CVE-2022-27449.json')),
    )
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'CVE-2022-27449.json',
        'original_sha256': _sha256('CVE-2022-27449.json'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update CVE-2022-27449', commit.message)
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_alpine', diff.patch)

    self.expect_dict_equal(
        'update_alpine',
        ndb.Key(osv.Bug, 'CVE-2022-27449').get()._to_dict(),
    )

    self.mock_publish.assert_not_called()

  def test_update_android(self):
    """Test updating Android through bucket entries."""
    self.source_repo.type = osv.SourceRepositoryType.BUCKET
    self.source_repo.bucket = TEST_BUCKET
    self.source_repo.editable = False
    self.source_repo.db_prefix.append('ASB-A-')
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

  def test_update_bad_ecosystem_new(self):
    """Test adding from an unsupported ecosystem."""
    self.mock_repo.add_file(
        'OSV-129.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-129.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-129.yaml',
        'original_sha256': _sha256('OSV-129.yaml'),
        'deleted': 'false',
    }

    with self.assertLogs(level='WARNING'):
      task_runner._source_update(message)

    bug = osv.Bug.get_by_id('OSV-129')
    self.assertEqual(osv.BugStatus.INVALID, bug.status)

  def test_update_partly_bad_ecosystem_new(self):
    """Test adding vuln with both supported and unsupported ecosystem."""
    self.mock_repo.add_file(
        'OSV-130.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'OSV-130.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-130.yaml',
        'original_sha256': _sha256('OSV-130.yaml'),
        'deleted': 'false',
    }

    with self.assertLogs(level='WARNING'):
      task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update OSV-130', commit.message)

    self.expect_dict_equal(
        'update_partly_bad_ecosystem_new',
        osv.Bug.get_by_id('OSV-130')._to_dict(),
    )

  def test_update_partly_bad_ecosystem_delete(self):
    """Test removal of only supported ecosystem in vulnerability with
        unsupported and supported ecosystems.
        """
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-131.yaml',
        'original_sha256': _sha256('OSV-131.yaml'),
        'deleted': 'false',
    }

    with self.assertLogs(level='WARNING'):
      task_runner._source_update(message)

    bug = osv.Bug.get_by_id('OSV-131')
    self.assertEqual(osv.BugStatus.INVALID, bug.status)

  def test_update_bucket_cve(self):
    """Test a bucket entry that is a converted CVE and doesn't have an ecosystem."""
    self.source_repo.type = osv.SourceRepositoryType.BUCKET
    self.source_repo.bucket = TEST_BUCKET
    self.source_repo.editable = False
    self.source_repo.db_prefix.append('CVE-')
    self.source_repo.put()

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)

    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'a/b/CVE-2022-0128.json',
        'original_sha256':
            ('a4060cb842363cb6ae7669057402ccddce21a94ed6cad98234e73305816a86d3'
            ),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    actual_result = osv.Bug.get_by_id('CVE-2022-0128')

    # Remove some values that make the diff super unwieldly
    for affected in actual_result.affected_packages:
      del affected.versions
    del actual_result.affected_fuzzy

    self.expect_dict_equal('update_bucket_cve', actual_result._to_dict())

  def test_last_affected_git(self):
    """Basic last_affected GIT enumeration."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = True
    # detect_cherrypicks should not cause result in cherrypick detection for
    # `last_affected`, since equivalent `last_affected` across different
    # branches likely no have relation to the actual vulnerable range.
    self.source_repo.detect_cherrypicks = True
    self.source_repo.put()

    self.mock_repo.add_file(
        'OSV-TEST-last-affected-01.yaml',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'OSV-TEST-last-affected-01.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-TEST-last-affected-01.yaml',
        'original_sha256': _sha256('OSV-TEST-last-affected-01.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()
    diff = repo.diff(commit.parents[0], commit)

    self.expect_equal('diff_last_affected_git', diff.patch)

    self.expect_dict_equal(
        'last_affected_git',
        ndb.Key(osv.Bug, 'OSV-TEST-last-affected-01').get()._to_dict(),
    )

    affected_commits = list(osv.AffectedCommits.query())
    self.assertEqual(1, len(affected_commits))
    affected_commits = affected_commits[0]

    self.assertCountEqual(
        [
            b'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
            b'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            b'8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        ],
        [codecs.encode(commit, 'hex') for commit in affected_commits.commits],
    )

  def test_invalid_prefix(self):
    """Test attempting to create a bug with a invalid db_prefix."""
    with self.assertRaises(ValueError):
      # Default db_prefix is `OSV-`
      osv.Bug(
          db_id='BLAH-131',
          project=['blah.com/package'],
          ecosystem=['ecosystem'],
          source_id='source:OSV-131.yaml',
          import_last_modified=datetime.datetime(
              2021, 1, 1, 0, 0, tzinfo=datetime.UTC),
          source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
      ).put()

  def test_dont_index_too_many_git_versions(self):
    """Test that we don't index too many versions from Git."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = True
    self.source_repo.detect_cherrypicks = True
    self.source_repo.put()

    # Use any valid OSV input test file here.
    self.mock_repo.add_file(
        'OSV-TEST-last-affected-01.yaml',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'OSV-TEST-last-affected-01.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'OSV-TEST-last-affected-01.yaml',
        'original_sha256': _sha256('OSV-TEST-last-affected-01.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    bug = ndb.Key(osv.Bug, 'OSV-TEST-last-affected-01').get()

    # Manually append versions over the expected version limit.
    bug.affected_packages[0].versions = ['%05d' % i for i in range(5001)]
    bug.put()
    self.expect_dict_equal('dont_index_too_many_git_versions', bug._to_dict())

  def test_analysis_crash_handling(self):
    """Test that formerly crash-inducing GIT events are handled gracefully."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = True
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('CVE-')
    self.source_repo.put()

    # Use any valid OSV input test file here.
    self.mock_repo.add_file(
        'CVE-2016-10046.json',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'CVE-2016-10046.json')),
    )
    self.mock_repo.commit('User', 'user@email')

    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'CVE-2016-10046.json',
        'original_sha256': _sha256('CVE-2016-10046.json'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    bug = osv.Bug.get_by_id('CVE-2016-10046')

    self.expect_dict_equal('analysis_crash_handling', bug._to_dict())

  def test_update_clears_stale_import_finding(self):
    """A subsequent successful update removes the now stale import finding."""

    # Add a pre-existing record import finding.

    osv.ImportFinding(
        bug_id='OSV-123',
        source='source',
        findings=[osv.ImportFindings.INVALID_JSON],
        first_seen=osv.utcnow(),
        last_attempt=osv.utcnow()).put()

    # Simulate a successful record update.

    self.test_update()

    # Check the pre-existing finding is no longer present.

    self.assertIsNone(
        osv.ImportFinding.get_by_id('OSV-123'),
        'Stale import finding still present after successful record processing')


def setUpModule():
    """Set up the test module."""
    print("Starting Datastore Emulator for the test suite...")
    global ds_emulator, ndb_client, context_manager
    ds_emulator = tests.start_datastore_emulator()
    ndb_client = ndb.Client()

    # Set the NDB client context for all tests in this module
    context_manager = ndb_client.context()
    # __enter__ is needed to activate the context
    context = context_manager.__enter__()
    context.set_memcache_policy(False)
    context.set_cache_policy(False)


def tearDownModule():
    """Tear down the test module."""
    print("Stopping Datastore Emulator.")
    # Deactivate the NDB context
    context_manager.__exit__(None, None, None)
    tests.stop_emulator()


if __name__ == '__main__':
    unittest.main()

