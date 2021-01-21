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
import worker

# pylint: disable=protected-access,invalid-name


class OssFuzzDetailsTest(unittest.TestCase):
  """Details generation tests."""

  def test_basic(self):
    """Basic tests."""
    crash_type = 'Heap-buffer-overflow'
    crash_state = 'Foo\nBar\nBlah\n'

    summary = worker.get_oss_fuzz_summary(crash_type, crash_state)
    self.assertEqual('Heap-buffer-overflow in Foo', summary)

    details = worker.get_oss_fuzz_details('1337', crash_type, crash_state)
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

    details = worker.get_oss_fuzz_details('', crash_type, crash_state)
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

    summary = worker.get_oss_fuzz_summary(crash_type, crash_state)
    self.assertEqual('ASSERT: idx < length', summary)

    details = worker.get_oss_fuzz_details('1337', crash_type, crash_state)
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

    summary = worker.get_oss_fuzz_summary(crash_type, crash_state)
    self.assertEqual('Bad-cast to A from B', summary)

    details = worker.get_oss_fuzz_details('1337', crash_type, crash_state)
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
    self.clone_repository_patcher = mock.patch('pygit2.clone_repository')
    self.maxDiff = None

    mock_clone = self.clone_repository_patcher.start()
    mock_clone.return_value = pygit2.Repository('osv-test')

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
        confidence=100,
        project='project',
        ecosystem='ecosystem',
        public=False)
    should_be_deleted.put()

  def tearDown(self):
    self.clone_repository_patcher.stop()

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

    worker.process_impact_task('oss-fuzz:123', message)
    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'additional_commit_ranges': [{
                'introduced_in': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'fixed_in': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98'
            }, {
                'introduced_in': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'fixed_in': None
            }],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'repo_url': 'https://repo.com/repo',
            'confidence': 100,
            'issue_id': '9001',
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'public': False,
            'reference_urls': ['https://url/'],
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual(100, commit.confidence)
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

    worker.process_impact_task('oss-fuzz:123', message)
    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch-v0.1.1-with-fix',
                'branch_1_cherrypick_regress', 'v0.1.1', 'v0.2'
            ],
            'affected_fuzzy': ['0-1-1', '0-1-1', '1', '0-1-1', '0-2'],
            'additional_commit_ranges': [],
            'fixed': ('b1c95a196f22d06fcf80df8c6691cd113d8fefff:'
                      '36f0bd9549298b44f9ff2496c9dd1326b3a9d0e2'),
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'repo_url': 'https://repo.com/repo',
            'confidence': 70,
            'issue_id': '9001',
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'reference_urls': ['https://url/'],
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual(70, commit.confidence)
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

    worker.process_impact_task('oss-fuzz:123', message)
    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch-v0.1.1-with-fix',
                'branch_1_cherrypick_regress', 'v0.1.1', 'v0.2'
            ],
            'affected_fuzzy': ['0-1-1', '0-1-1', '1', '0-1-1', '0-2'],
            'additional_commit_ranges': [],
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'fixed': ('eefe8ec3f1f90d0e684890e810f3f21e8500a4cd:'
                      'b587c21c36a84e16cfc6b39eb68578d43b5281ad'),
            'repo_url': 'https://repo.com/repo',
            'confidence': 30,
            'issue_id': '9001',
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'reference_urls': ['https://url/'],
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual(30, commit.confidence)
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

    worker.process_impact_task('oss-fuzz:123', message)
    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'additional_commit_ranges': [],
            'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            'regressed': 'unknown:eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'repo_url': 'https://repo.com/repo',
            'confidence': 80,
            'issue_id': '9001',
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'reference_urls': ['https://url/'],
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual(80, commit.confidence)
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

    worker.process_impact_task('oss-fuzz:123', message)
    self.assertDictEqual(
        {
            'affected':
                ['branch-v0.1.1', 'branch_1_cherrypick_regress', 'v0.1.1'],
            'affected_fuzzy': ['0-1-1', '1', '0-1-1'],
            'additional_commit_ranges': [{
                'introduced_in': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
                'fixed_in': 'b9b3fd4732695b83c3068b7b6a14bb372ec31f98'
            }, {
                'introduced_in': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'fixed_in': None
            }],
            'fixed': '8d8242f545e9cec3e6d0d2e3f5bde8be1c659735',
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'repo_url': 'https://repo.com/repo',
            'confidence': 100,
            'issue_id': '9001',
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'reference_urls': ['https://url/'],
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
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

    worker.process_impact_task('oss-fuzz:123', message)
    self.assertDictEqual(
        {
            'affected': [
                'branch-v0.1.1', 'branch-v0.1.1-with-fix',
                'branch_1_cherrypick_regress', 'v0.1.1', 'v0.2'
            ],
            'affected_fuzzy': ['0-1-1', '0-1-1', '1', '0-1-1', '0-2'],
            'additional_commit_ranges': [{
                'introduced_in': 'febfac1940086bc1f6d3dc33fda0a1d1ba336209',
                'fixed_in': None
            }],
            'fixed': '',
            'regressed': 'eefe8ec3f1f90d0e684890e810f3f21e8500a4cd',
            'repo_url': 'https://repo.com/repo',
            'confidence': 100,
            'issue_id': '9001',
            'timestamp': datetime.datetime(2020, 1, 1),
            'source_id': 'oss-fuzz:123',
            'project': 'project',
            'ecosystem': 'ecosystem',
            'summary': 'Heap-buffer-overflow in Foo',
            'details': 'DETAILS',
            'severity': 'MEDIUM',
            'sort_key': '2020-0001337',
            'reference_urls': ['https://url/'],
            'public': False,
            'status': osv.BugStatus.PROCESSED.value,
            'has_affected': True,
            'search_indices': ['project', '2020-1337', '2020', '1337'],
        },
        ndb.Key(osv.Bug, '2020-1337').get()._to_dict())

    affected_commits = list(osv.AffectedCommit.query())
    for commit in affected_commits:
      self.assertEqual(100, commit.confidence)
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
    self.clone_repository_patcher = mock.patch('pygit2.clone_repository')
    mock_clone = self.clone_repository_patcher.start()
    mock_clone.return_value = pygit2.Repository('osv-test')

    osv.Bug(
        id='2020-1', project='project', affected=['v0.1.1'], public=True).put()
    osv.Bug(
        id='2020-2', project='project', affected=['v0.2'], public=False).put()

  def tearDown(self):
    self.clone_repository_patcher.stop()

  def test_package_info(self):
    """Test project info task."""
    message = mock.Mock()
    message.attributes = {
        'package_name': 'project',
        'ecosystem': 'ecosystem',
        'repo_url': 'https://repo.com/repo',
    }

    worker.process_package_info_task(message)

    package_info = ndb.Key(osv.PackageInfo, 'ecosystem/project').get()
    self.assertEqual('branch_1_cherrypick_regress', package_info.latest_tag)

    tags_without_bugs = [
        'branch-v0.1.1',
        'branch-v0.1.1-with-fix',
        'branch_1_cherrypick_regress',
        'v0.1',
    ]

    for tag in tags_without_bugs:
      tag_info = ndb.Key(osv.PackageTagInfo, 'ecosystem/project-' + tag).get()
      self.assertIsNotNone(tag_info)
      self.assertEqual('project', tag_info.package)
      self.assertEqual(tag, tag_info.tag)
      self.assertListEqual([], tag_info.bugs)
      self.assertListEqual([], tag_info.bugs_private)

    tag_info = ndb.Key(osv.PackageTagInfo, 'ecosystem/project-v0.1.1').get()
    self.assertEqual('project', tag_info.package)
    self.assertEqual('v0.1.1', tag_info.tag)
    self.assertListEqual(['2020-1'], tag_info.bugs)
    self.assertListEqual([], tag_info.bugs_private)

    tag_info = ndb.Key(osv.PackageTagInfo, 'ecosystem/project-v0.2').get()
    self.assertEqual('project', tag_info.package)
    self.assertEqual('v0.2', tag_info.tag)
    self.assertListEqual([], tag_info.bugs)
    self.assertListEqual(['2020-2'], tag_info.bugs_private)


class EcosystemTest(unittest.TestCase):
  """Test getting ecosystem."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    self.oss_fuzz_checkout = os.path.join(self.tmp_dir, 'oss-fuzz')
    worker.ensure_updated_checkout(worker.OSS_FUZZ_GIT_URL,
                                   self.oss_fuzz_checkout)

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_get_ecosystem(self):
    """Test getting ecosystems."""
    self.assertEqual('pypi',
                     worker.get_ecosystem(self.oss_fuzz_checkout, 'pillow'))
    self.assertEqual(
        'golang', worker.get_ecosystem(self.oss_fuzz_checkout,
                                       'golang-protobuf'))
    self.assertEqual('cargo',
                     worker.get_ecosystem(self.oss_fuzz_checkout, 'servo'))
    self.assertEqual('', worker.get_ecosystem(self.oss_fuzz_checkout,
                                              'openssl'))


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
    commit = worker.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '949f182716f037e25394bbb98d39b3295d230a29', 'oss-fuzz:133713371337',
        '12345')
    self.assertEqual('57e58a5d7c2bb3ce0f04f17ec0648b92ee82531f', commit)

    commit = worker.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '25147a74d8aeb27b43665530ee121a2a1b19dc58', 'oss-fuzz:133713371337',
        '12345')
    self.assertEqual('25147a74d8aeb27b43665530ee121a2a1b19dc58', commit)

  def test_has_testcase_id(self):
    """Test identifying the commit that has the testcase ID."""
    commit = worker.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '00514d6f244f696e750a37083163992c6a50cfd3', 'oss-fuzz:133713371337',
        '12345')

    self.assertEqual('90aa4127295b2c37b5f7fcf6a9772b12c99a5212', commit)

  def test_has_oss_fuzz_reference(self):
    """Test identifying the commit that has the testcase ID."""
    commit = worker.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        'b1fa81a5d59e9b4d6e276d82fc17058f3cf139d9', 'oss-fuzz:133713371337',
        '12345')

    self.assertEqual('3c5dcf6a5bec14baab3b247d369a7270232e1b83', commit)

  def test_has_multiple_oss_fuzz_reference(self):
    commit = worker.find_oss_fuzz_fix_via_commit(
        self.repo, 'e1b045257bc5ca2a11d0476474f45ef77a0366c7',
        '949f182716f037e25394bbb98d39b3295d230a29', 'oss-fuzz:7331', '54321')
    self.assertIsNone(commit)


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
