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
import datetime
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
        'Crash type: Heap-buffer-overflow\n'
        'Crash state:\n'
        'Foo\n'
        'Bar\n'
        'Blah\n', details)

  def test_no_issue(self):
    """Test generating details without an issue ID."""
    crash_type = 'Heap-buffer-overflow'
    crash_state = 'Foo\nBar\nBlah\n'

    details = oss_fuzz.get_oss_fuzz_details('', crash_type, crash_state)
    self.assertEqual(
        'Crash type: Heap-buffer-overflow\n'
        'Crash state:\n'
        'Foo\n'
        'Bar\n'
        'Blah\n', details)

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
        'Crash type: ASSERT\n'
        'Crash state:\n'
        'idx < length\n'
        'Foo\n'
        'Bar\n', details)

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
        'Crash type: Bad-cast\n'
        'Crash state:\n'
        'Bad-cast to A from B\n'
        'Foo\n'
        'Bar\n', details)


class ImpactTest(unittest.TestCase):
  """Impact task tests."""

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None

    tests.mock_clone(self, return_value=pygit2.Repository('osv-test'))
    tests.mock_datetime(self)

    allocated_bug = osv.Bug(
        id='2020-1337',
        timestamp=datetime.datetime(2020, 1, 1),
        source_id='oss-fuzz:123',
        status=osv.BugStatus.UNPROCESSED,
        public=False)
    allocated_bug.put()

    should_be_deleted = osv.AffectedCommit(
        id='2020-1337-abcd',
        bug_id='2020-1337',
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
        'allocated_id': '2020-1337',
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
    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'affected_ranges': [{
                'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }, {
                'fixed': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }, {
                'fixed': '',
                'introduced': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }],
            'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'issue_id': '9001',
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'source_of_truth': osv.SourceOfTruth.INTERNAL,
            'public': False,
            'reference_url_types': {
                'https://url/': 'WEB'
            },
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'oss-fuzz',
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual('project', commit.project)

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
        'allocated_id': '2020-1337',
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
    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch-v0.1.1-with-fix',
                'branch_1_cherrypick_regress', 'v0.1.1', 'v0.2'
            ],
            'affected_fuzzy': ['0-1-1', '0-1-1', '1', '0-1-1', '0-2'],
            'affected_ranges': [{
                'fixed': 'b1c95a196f22d06fcf80df8c6691cd113d8fefff:'
                         '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }],
            'fixed': ('b1c95a196f22d06fcf80df8c6691cd113d8fefff:'
                      '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2'),
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'issue_id': '9001',
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'reference_url_types': {
                'https://url/': 'WEB'
            },
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'source_of_truth': osv.SourceOfTruth.INTERNAL,
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'oss-fuzz',
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual('project', commit.project)

    self.assertCountEqual([
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
        'allocated_id': '2020-1337',
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
    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch-v0.1.1-with-fix',
                'branch_1_cherrypick_regress', 'v0.1.1', 'v0.2'
            ],
            'affected_fuzzy': ['0-1-1', '0-1-1', '1', '0-1-1', '0-2'],
            'affected_ranges': [{
                'fixed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd:'
                         'b587c21c36a84e16cfc6b39eb68578d43b5281ad',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }],
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'fixed': ('eefe8ec3f1f90d0e684890e810f3f21e8500a4cd:'
                      'b587c21c36a84e16cfc6b39eb68578d43b5281ad'),
            'issue_id': '9001',
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'reference_url_types': {
                'https://url/': 'WEB'
            },
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'source_of_truth': osv.SourceOfTruth.INTERNAL,
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'oss-fuzz',
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual('project', commit.project)

    self.assertCountEqual([
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
        'allocated_id': '2020-1337',
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
    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'affected_ranges': [{
                'fixed':
                    '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced':
                    'unknown:eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url':
                    'https://repo.com/repo',
                'type':
                    'GIT'
            }],
            'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            'regressed': 'unknown:eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'issue_id': '9001',
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'source_of_truth': osv.SourceOfTruth.INTERNAL,
            'reference_url_types': {
                'https://url/': 'WEB'
            },
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'oss-fuzz',
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual('project', commit.project)

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
        'allocated_id': '2020-1337',
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
    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'affected_ranges': [{
                'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }, {
                'fixed': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }, {
                'fixed': '',
                'introduced': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }],
            'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'issue_id': '9001',
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'source_of_truth': osv.SourceOfTruth.INTERNAL,
            'reference_url_types': {
                'https://url/': 'WEB'
            },
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'oss-fuzz',
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

  def test_not_fixed(self):
    """Test not fixed bug."""
    message = mock.Mock()
    message.attributes = {
        'source_id': 'oss-fuzz:123',
        'allocated_id': '2020-1337',
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
    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch-v0.1.1-with-fix',
                'branch_1_cherrypick_regress', 'v0.1.1', 'v0.2'
            ],
            'affected_fuzzy': ['0-1-1', '0-1-1', '1', '0-1-1', '0-2'],
            'affected_ranges': [{
                'fixed': '',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }, {
                'fixed': '',
                'introduced': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'repo_url': 'https://repo.com/repo',
                'type': 'GIT'
            }],
            'fixed': '',
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'issue_id': '9001',
            'is_fixed': False,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'source_of_truth': osv.SourceOfTruth.INTERNAL,
            'reference_url_types': {
                'https://url/': 'WEB'
            },
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'oss-fuzz',
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual('project', commit.project)

    self.assertCountEqual([
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2',
        '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
        'b587c21c36a84e16cfc6b39eb68578d43b5281ad',
        '88e5ae3c40c85b702ba89a34c29f233048abb12b',
        '3ea6feea9bb853596c727abab309476cc07d1505',
    ], [commit.commit for commit in affected_commits])


class PackageInfoTests(unittest.TestCase):
  """package_info tests."""

  def setUp(self):
    tests.reset_emulator()
    tests.mock_clone(self, return_value=pygit2.Repository('osv-test'))

    osv.Bug(
        id='2020-1',
        project='project',
        ecosystem='ecosystem',
        affected=['v0.1.1'],
        public=True).put()
    osv.Bug(
        id='2020-2',
        project='project',
        ecosystem='ecosystem',
        affected=['v0.2'],
        public=False).put()
    osv.PackageTagInfo(
        id='ecosystem/project-v0.1.6',
        package='project',
        ecosystem='ecosystem',
        tag='v0.1.6').put()

  def test_package_info(self):
    """Test project info task."""
    message = mock.Mock()
    message.attributes = {
        'package_name': 'project',
        'ecosystem': 'ecosystem',
    }

    worker.process_package_info_task(message)

    tag_info = ndb.Key(osv.PackageTagInfo, 'ecosystem/project-v0.1.1').get()
    self.assertEqual('project', tag_info.package)
    self.assertEqual('v0.1.1', tag_info.tag)
    self.assertListEqual(['OSV-2020-1'], tag_info.bugs)

    self.assertIsNone(
        ndb.Key(osv.PackageTagInfo, 'ecosystem/project-v0.2').get())
    self.assertIsNone(
        ndb.Key(osv.PackageTagInfo, 'ecosystem/project-v0.1.6').get())


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
    osv.Bug(id='2021-1', source_id='oss-fuzz:1337').put()
    osv.AffectedCommit(bug_id='2021-1').put()
    osv.AffectedCommit(bug_id='2021-1').put()

    message = mock.Mock()
    message.attributes = {
        'type': 'invalid',
        'testcase_id': '1337',
        'source_id': '',
    }

    worker.mark_bug_invalid(message)
    bug = ndb.Key(osv.Bug, '2021-1').get()
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


class UpdateTest(unittest.TestCase):
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
    self.mock_repo.commit('User', 'user@email')

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.GIT,
        id='source',
        name='source',
        repo_url='file://' + self.remote_source_repo_path,
        editable=True,
        repo_username='')
    self.source_repo.put()

    osv.Bug(
        id='BLAH-123',
        project='blah.com/package',
        ecosystem='golang',
        source_id='source:BLAH-123.yaml',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()
    osv.Bug(
        id='BLAH-124',
        regressed='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        project='blah.com/package',
        ecosystem='golang',
        source_id='source:BLAH-124.yaml',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()
    osv.Bug(
        id='BLAH-125',
        regressed='eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        fixed='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
        project='blah.com/package',
        ecosystem='golang',
        source_id='source:BLAH-125.yaml',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()
    osv.Bug(
        id='BLAH-127',
        project='blah.com/package',
        ecosystem='golang',
        source_id='source:BLAH-127.yaml',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO).put()

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
        'original_sha256': ('f791309e3ede0c516167652ccf2c6582'
                            'a1bbd8dc38bfa711ac2b6f0f4d5b6a22'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-123', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.assertEqual(self._load_test_data('expected.diff'), diff.patch)

    self.assertDictEqual(
        {
            'affected_ranges': [{
                'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': '',
                'introduced': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }],
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'details': 'Blah blah blah\nBlah\n',
            'ecosystem': 'golang',
            'fixed': '',
            'has_affected': True,
            'issue_id': None,
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'project': 'blah.com/package',
            'public': True,
            'reference_url_types': {
                'https://ref.com/ref': 'WEB'
            },
            'regressed': '',
            'search_indices': ['blah.com/package', 'BLAH-123', 'BLAH', '123'],
            'severity': 'HIGH',
            'sort_key': 'BLAH-0000123',
            'source_id': 'source:BLAH-123.yaml',
            'source_of_truth': osv.SourceOfTruth.SOURCE_REPO,
            'status': None,
            'summary': 'A vulnerability',
            'timestamp': None,
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'source',
        },
        osv.Bug.get_by_id('BLAH-123')._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertCountEqual([
        '4c155795426727ea05575bd5904321def23c03f4',
        'b1c95a196f22d06fcf80df8c6691cd113d8fefff',
        'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
        'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
        'ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b',
    ], [commit.commit for commit in affected_commits])

  def test_update_add_fix(self):
    """Test basic update adding a fix."""
    fix_result = osv.FixResult(
        id='source:BLAH-124.yaml',
        commit='8d8242f545e9cec3e6d0d2e3f5bde8be1c659735')
    fix_result.put()
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'BLAH-124.yaml',
        'original_sha256': ('323bdd5d8cc8c771d6aac84426a57dd6'
                            '00995702fcb021b7fe9afd082b8a6e4c'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-124', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.assertEqual(self._load_test_data('expected_add_fix.diff'), diff.patch)

    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'affected_ranges': [{
                'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': '',
                'introduced': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }],
            'details': 'Blah blah blah\nBlah\n',
            'ecosystem': 'golang',
            'fixed': '',
            'has_affected': True,
            'issue_id': None,
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'project': 'blah.com/package',
            'public': True,
            'reference_url_types': {
                'https://ref.com/ref': 'WEB'
            },
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'search_indices': ['blah.com/package', 'BLAH-124', 'BLAH', '124'],
            'severity': 'HIGH',
            'sort_key': 'BLAH-0000124',
            'source_id': 'source:BLAH-124.yaml',
            'source_of_truth': osv.SourceOfTruth.SOURCE_REPO,
            'status': None,
            'summary': 'A vulnerability',
            'timestamp': None,
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'source',
        },
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
        'original_sha256': ('d00c24789be7ea03ac6ac97b321ffa5b'
                            '9380d13f510b13723fb5bb66a0ca4338'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-127', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.assertEqual(self._load_test_data('expected_127.diff'), diff.patch)

    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1', 'v0.1.1'
            ],
            'affected_fuzzy': ['0-1-1', '1', '0-1', '0-1-1'],
            'affected_ranges': [{
                'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced': '',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
                'introduced': '',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }],
            'details': 'Blah blah blah\nBlah\n',
            'ecosystem': 'golang',
            'fixed': '',
            'has_affected': True,
            'issue_id': None,
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'project': 'blah.com/package',
            'public': True,
            'reference_url_types': {
                'https://ref.com/ref': 'WEB'
            },
            'regressed': '',
            'search_indices': ['blah.com/package', 'BLAH-127', 'BLAH', '127'],
            'severity': 'HIGH',
            'sort_key': 'BLAH-0000127',
            'source_id': 'source:BLAH-127.yaml',
            'source_of_truth': osv.SourceOfTruth.SOURCE_REPO,
            'status': None,
            'summary': 'A vulnerability',
            'timestamp': None,
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'source',
        },
        osv.Bug.get_by_id('BLAH-127')._to_dict())

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
        'original_sha256': ('5e1c2f30f6312cb16f5eedac88f92992'
                            'dd015e2891d17e84ee2ab8af78b801b9'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update BLAH-126', commit.message)

    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'affected_ranges': [{
                'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98',
                'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }, {
                'fixed': '',
                'introduced': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'repo_url': 'https://osv-test/repo/url',
                'type': 'GIT'
            }],
            'details': 'Blah blah blah\nBlah\n',
            'ecosystem': 'golang',
            'fixed': '',
            'has_affected': True,
            'issue_id': None,
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'project': 'blah.com/package',
            'public': True,
            'reference_url_types': {
                'https://ref.com/ref': 'WEB'
            },
            'regressed': '',
            'search_indices': ['blah.com/package', 'BLAH-126', 'BLAH', '126'],
            'severity': 'HIGH',
            'sort_key': 'BLAH-0000126',
            'source_id': 'source:BLAH-126.yaml',
            'source_of_truth': osv.SourceOfTruth.SOURCE_REPO,
            'status': osv.BugStatus.PROCESSED,
            'summary': 'A vulnerability',
            'timestamp': datetime.datetime(2021, 1, 1, 0, 0),
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'source',
        },
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
        'original_sha256': ('f791309e3ede0c516167652ccf2c6582'
                            'a1bbd8dc38bfa711ac2b6f0f4d5b6a22'),
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
        'original_sha256': ('f3914d12891a3a441cb19cfe5c11f9b6'
                            'b5cd0c87c3c14c40d54559dad4bb813a'),
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
        'original_sha256': ('f791309e3ede0c516167652ccf2c6582'
                            'a1bbd8dc38bfa711ac2b6f0f4d5b6a22'),
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
    self.source_repo.ignore_git = True
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
        'original_sha256': ('c8313271c17c169afd795e7006d5b7f9'
                            'd692359904c1c9bca39a007e3963f1c6'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Update PYSEC-123', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.assertEqual(self._load_test_data('expected_pypi.diff'), diff.patch)

    self.assertDictEqual(
        {
            'affected': [
                '1.14.2', '1.15.0', '1.15.0rc1', '1.16.0', '1.16.0rc1',
                '1.16.1', '1.16.1rc1', '1.17.0', '1.17.0rc1', '1.17.1',
                '1.17.1rc1', '1.18.0', '1.18.0rc1', '1.19.0', '1.19.0rc1',
                '1.20.0', '1.20.0rc1', '1.20.0rc2', '1.20.0rc3', '1.20.1',
                '1.21.0rc1', '1.21.1', '1.21.1rc1', '1.22.0', '1.22.0rc1',
                '1.22.1', '1.23.0', '1.23.0rc1', '1.23.1', '1.24.0',
                '1.24.0rc1', '1.24.1', '1.24.3', '1.25.0', '1.25.0rc1',
                '1.26.0', '1.26.0rc1', '1.27.0rc1', '1.27.0rc2', '1.27.1',
                '1.27.2', '1.28.0.dev0', '1.28.0rc1', '1.28.0rc2', '1.28.0rc3',
                '1.28.1', '1.29.0', '1.30.0', '1.30.0rc1', '1.31.0rc1',
                '1.31.0rc2'
            ],
            'affected_fuzzy': [
                '1-14-2', '1-15-0', '1-15-0-rc1', '1-16-0', '1-16-0-rc1',
                '1-16-1', '1-16-1-rc1', '1-17-0', '1-17-0-rc1', '1-17-1',
                '1-17-1-rc1', '1-18-0', '1-18-0-rc1', '1-19-0', '1-19-0-rc1',
                '1-20-0', '1-20-0-rc1', '1-20-0-rc2', '1-20-0-rc3', '1-20-1',
                '1-21-0-rc1', '1-21-1', '1-21-1-rc1', '1-22-0', '1-22-0-rc1',
                '1-22-1', '1-23-0', '1-23-0-rc1', '1-23-1', '1-24-0',
                '1-24-0-rc1', '1-24-1', '1-24-3', '1-25-0', '1-25-0-rc1',
                '1-26-0', '1-26-0-rc1', '1-27-0-rc1', '1-27-0-rc2', '1-27-1',
                '1-27-2', '1-28-0-0', '1-28-0-rc1', '1-28-0-rc2', '1-28-0-rc3',
                '1-28-1', '1-29-0', '1-30-0', '1-30-0-rc1', '1-31-0-rc1',
                '1-31-0-rc2'
            ],
            'affected_ranges': [
                {
                    'fixed': '1.31.0',
                    'introduced': '1.14.2',
                    'repo_url': '',
                    'type': 'ECOSYSTEM'
                },
                {
                    'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
                    'introduced': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                    'repo_url': 'https://osv-test/repo/url',
                    'type': 'GIT'
                },
            ],
            'details': 'Blah blah blah\nBlah\n',
            'ecosystem': 'PyPI',
            'fixed': '',
            'has_affected': True,
            'issue_id': None,
            'is_fixed': True,
            'last_modified': datetime.datetime(2021, 1, 1, 0, 0),
            'project': 'grpcio',
            'public': True,
            'reference_url_types': {
                'https://ref.com/ref': 'WEB'
            },
            'regressed': '',
            'search_indices': ['grpcio', 'PYSEC-123', 'PYSEC', '123'],
            'severity': None,
            'sort_key': 'PYSEC-0000123',
            'source_id': 'source:PYSEC-123.yaml',
            'source_of_truth': osv.SourceOfTruth.SOURCE_REPO,
            'status': osv.BugStatus.PROCESSED,
            'summary': 'A vulnerability',
            'timestamp': datetime.datetime(2021, 1, 1, 0, 0),
            'ecosystem_specific': None,
            'database_specific': None,
            'semver_fixed_indexes': [],
            'source': 'source',
        },
        osv.Bug.get_by_id('PYSEC-123')._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    self.assertEqual(0, len(affected_commits))

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

    self.assertDictEqual(
        {
            'affected': [],
            'affected_fuzzy': [],
            'affected_ranges': [{
                'fixed': 'v1.0.0-rc8.0.20190930145003-cad42f6e0932',
                'introduced': '',
                'repo_url': '',
                'type': 'SEMVER'
            }],
            'details':
                'AppArmor restrictions may be bypassed due to improper '
                'validation of mount\n'
                'targets, allowing a malicious image to mount volumes over e.g.'
                ' /proc.\n',
            'ecosystem':
                'Go',
            'fixed':
                '',
            'has_affected':
                True,
            'is_fixed':
                True,
            'issue_id':
                None,
            'last_modified':
                datetime.datetime(2021, 4, 14, 12, 0),
            'project':
                'github.com/opencontainers/runc/libcontainer',
            'public':
                True,
            'reference_url_types': {
                'https://github.com/opencontainers/runc/commit/'
                'cad42f6e0932db0ce08c3a3d9e89e6063ec283e4':
                    'FIX',
                'https://github.com/opencontainers/runc/issues/2128':
                    'WEB',
                'https://github.com/opencontainers/runc/pull/2130':
                    'FIX'
            },
            'regressed':
                '',
            'search_indices': [
                'github.com/opencontainers/runc/libcontainer', 'GO-2021-0085',
                'GO', '2021', '0085'
            ],
            'severity':
                None,
            'sort_key':
                'GO-0002021',
            'source_id':
                'source:a/b/test.json',
            'source':
                'source',
            'source_of_truth':
                2,
            'status':
                1,
            'summary':
                '',
            'timestamp':
                datetime.datetime(2021, 4, 14, 12, 0),
            'ecosystem_specific': {
                'url': 'https://go.googlesource.com/vulndb/+/refs/'
                       'heads/main/reports/GO-2021-0085.toml'
            },
            'database_specific':
                None,
            'semver_fixed_indexes': [
                '00000001.00000000.00000000-1rc8.'
                '00000000.120190930145003-cad42f6e0932'
            ],
        },
        osv.Bug.get_by_id('GO-2021-0085')._to_dict())
    self.assertDictEqual(
        {
            'affected': [],
            'affected_fuzzy': [],
            'affected_ranges': [{
                'fixed': 'v1.0.0-rc9.0.20200122160610-2fc03cc11c77',
                'introduced': '',
                'repo_url': '',
                'type': 'SEMVER'
            }],
            'details':
                'A race while mounting volumes allows a possible '
                'symlink-exchange\n'
                'attack, allowing a user whom can start multiple containers '
                'with\n'
                'custom volume mount configurations to escape the container.\n'
                '\n',
            'ecosystem': 'Go',
            'fixed': '',
            'has_affected': True,
            'is_fixed': True,
            'issue_id': None,
            'last_modified': datetime.datetime(2021, 4, 14, 12, 0),
            'project': 'github.com/opencontainers/runc/libcontainer',
            'public': True,
            'reference_url_types': {
                'https://github.com/opencontainers/runc/commit/'
                '2fc03cc11c775b7a8b2e48d7ee447cb9bef32ad0':
                    'FIX',
                'https://github.com/opencontainers/runc/issues/2197':
                    'WEB',
                'https://github.com/opencontainers/runc/pull/2207':
                    'FIX'
            },
            'regressed': '',
            'search_indices': [
                'github.com/opencontainers/runc/libcontainer', 'GO-2021-0087',
                'GO', '2021', '0087'
            ],
            'severity': None,
            'sort_key': 'GO-0002021',
            'source_id': 'source:a/b/test.json',
            'source_of_truth': 2,
            'status': 1,
            'summary': '',
            'timestamp': datetime.datetime(2021, 4, 14, 12, 0),
            'ecosystem_specific': {
                'Symbols': ['mountToRootfs'],
                'url': 'https://go.googlesource.com/vulndb/+/refs/'
                       'heads/main/reports/GO-2021-0087.toml'
            },
            'database_specific': None,
            'semver_fixed_indexes': [
                '00000001.00000000.00000000-1rc9.'
                '00000000.120200122160610-2fc03cc11c77'
            ],
            'source': 'source',
        },
        osv.Bug.get_by_id('GO-2021-0087')._to_dict())


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
