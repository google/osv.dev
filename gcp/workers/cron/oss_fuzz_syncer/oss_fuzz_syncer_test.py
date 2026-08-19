# Copyright 2024 Google LLC
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
"""Tests for oss_fuzz_syncer."""

import datetime
import io
import json
import os
import shutil
import tempfile
import unittest
from unittest import mock

import yaml

from gcp.workers.cron.oss_fuzz_syncer import oss_fuzz_syncer


class SyncerHelpersTest(unittest.TestCase):
  """Tests for syncer helper functions."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_is_wontfix(self):
    """Test is_wontfix helper."""
    self.assertTrue(
        oss_fuzz_syncer.is_wontfix(
            {'issueState': {
                'status': 'NOT_REPRODUCIBLE'
            }}))
    self.assertTrue(
        oss_fuzz_syncer.is_wontfix(
            {'issueState': {
                'status': 'INTENDED_BEHAVIOUR'
            }}))
    self.assertTrue(
        oss_fuzz_syncer.is_wontfix({'issueState': {
            'status': 'OBSOLETE'
        }}))
    self.assertTrue(
        oss_fuzz_syncer.is_wontfix({'issueState': {
            'status': 'INFEASIBLE'
        }}))
    self.assertFalse(
        oss_fuzz_syncer.is_wontfix({'issueState': {
            'status': 'FIXED'
        }}))
    self.assertFalse(
        oss_fuzz_syncer.is_wontfix({'issueState': {
            'status': 'NEW'
        }}))
    self.assertFalse(oss_fuzz_syncer.is_wontfix({}))

  def test_is_fixed(self):
    """Test is_fixed helper."""
    self.assertTrue(
        oss_fuzz_syncer.is_fixed({'issueState': {
            'status': 'FIXED'
        }}))
    self.assertTrue(
        oss_fuzz_syncer.is_fixed({'issueState': {
            'status': 'VERIFIED'
        }}))
    self.assertFalse(
        oss_fuzz_syncer.is_fixed({'issueState': {
            'status': 'NEW'
        }}))
    self.assertFalse(
        oss_fuzz_syncer.is_fixed({'issueState': {
            'status': 'NOT_REPRODUCIBLE'
        }}))
    self.assertFalse(oss_fuzz_syncer.is_fixed({}))

  def test_get_sanitizer_name(self):
    """Test get_sanitizer_name helper."""
    self.assertEqual(
        'address', oss_fuzz_syncer.get_sanitizer_name('libfuzzer_asan_project'))
    self.assertEqual('memory',
                     oss_fuzz_syncer.get_sanitizer_name('afl_msan_project'))
    self.assertEqual(
        'undefined',
        oss_fuzz_syncer.get_sanitizer_name('libfuzzer_ubsan_project'))
    with self.assertRaises(ValueError):
      oss_fuzz_syncer.get_sanitizer_name('unknown_job_type')

  def test_get_main_repo(self):
    """Test get_main_repo helper."""
    project_dir = os.path.join(self.tmp_dir, 'projects', 'test_proj')
    os.makedirs(project_dir, exist_ok=True)
    with open(os.path.join(project_dir, 'project.yaml'), 'w') as f:
      yaml.dump({'main_repo': 'https://github.com/example/test_proj.git'}, f)

    self.assertEqual('https://github.com/example/test_proj.git',
                     oss_fuzz_syncer.get_main_repo(self.tmp_dir, 'test_proj'))

  @mock.patch('urllib.request.urlopen')
  def test_get_commit(self, mock_urlopen):
    """Test get_commit helper."""
    srcmap_data = {
        '/src/test_proj': {
            'url': 'https://github.com/example/test_proj.git',
            'rev': 'abcdef1234567890'
        },
        '/src/dep': {
            'url': 'https://github.com/example/dep',
            'rev': '1111222233334444'
        }
    }
    mock_urlopen.return_value.__enter__.return_value = io.BytesIO(
        json.dumps(srcmap_data).encode('utf-8'))

    commit = oss_fuzz_syncer.get_commit(
        'https://storage.googleapis.com/bucket/123.srcmap.json',
        'https://github.com/example/test_proj')
    self.assertEqual('abcdef1234567890', commit)

  @mock.patch('urllib.request.urlopen')
  def test_get_commits(self, mock_urlopen):
    """Test get_commits helper."""
    srcmaps = {
        '100': {
            '/src/test_proj': {
                'url': 'https://github.com/example/test_proj',
                'rev': 'commit100'
            }
        },
        '200': {
            '/src/test_proj': {
                'url': 'https://github.com/example/test_proj',
                'rev': 'commit200'
            }
        }
    }

    def fake_urlopen(url):
      for rev, data in srcmaps.items():
        if f'{rev}.srcmap.json' in url:
          return io.BytesIO(json.dumps(data).encode('utf-8'))
      raise ValueError(f'Unknown url {url}')

    mock_urlopen.side_effect = lambda req: mock.MagicMock(
        __enter__=lambda s: fake_urlopen(req), __exit__=lambda *args: None)

    cf_testcase = {
        'additional_metadata':
            json.dumps({'build_url': 'gs://bucket/build-100.zip'})
    }

    old_commit, new_commit = oss_fuzz_syncer.get_commits(
        cf_testcase, 'https://github.com/example/test_proj', '100:200')
    self.assertEqual('commit100', old_commit)
    self.assertEqual('commit200', new_commit)


class SyncerProcessTest(unittest.TestCase):
  """Tests for Syncer issue processing and task generation."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    project_dir = os.path.join(self.tmp_dir, 'projects', 'test_proj')
    os.makedirs(project_dir, exist_ok=True)
    with open(os.path.join(project_dir, 'project.yaml'), 'w') as f:
      yaml.dump({'main_repo': 'https://github.com/example/test_proj'}, f)

    self.mock_osv_db = mock.MagicMock()
    self.mock_oss_fuzz_db = mock.MagicMock()
    self.mock_publisher = mock.MagicMock()
    self.mock_storage = mock.MagicMock()

    ds_patch = mock.patch('google.cloud.datastore.Client')
    pub_patch = mock.patch('google.cloud.pubsub_v1.PublisherClient')
    storage_patch = mock.patch(
        'google.cloud.storage.Client.create_anonymous_client')

    with ds_patch as mock_ds_client, \
         pub_patch as mock_pub_client, \
         storage_patch as mock_storage_client:
      mock_ds_client.side_effect = [self.mock_osv_db, self.mock_oss_fuzz_db]
      mock_pub_client.return_value = self.mock_publisher
      mock_storage_client.return_value = self.mock_storage

      self.syncer = oss_fuzz_syncer.Syncer(
          oss_fuzz_dir=self.tmp_dir,
          dry_run=False,
          osv_project='test-osv-project',
          clusterfuzz_project='test-cf-project')

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_process_issue_wontfix(self):
    """Test process_issue for wontfix issues."""
    mock_testcase = mock.MagicMock()
    mock_testcase.key.id = 123456
    self.syncer.get_oss_fuzz_testcase = mock.MagicMock(
        return_value=mock_testcase)

    issue = {'issueId': '999', 'issueState': {'status': 'NOT_REPRODUCIBLE'}}
    self.syncer.process_issue(issue)

    self.mock_publisher.publish.assert_called_once_with(
        'projects/test-osv-project/topics/tasks',
        b'',
        type='invalid',
        source_id='oss-fuzz:123456',
        testcase_id='123456')

  @mock.patch.object(oss_fuzz_syncer, 'get_commits')
  def test_process_issue_regression_and_fixed(self, mock_get_commits):
    """Test process_issue dispatches regression and fixed tasks."""
    mock_get_commits.side_effect = [
        ('regress_old', 'regress_new'),
        ('fix_old', 'fix_new'),
    ]

    mock_testcase = mock.MagicMock()
    mock_testcase.key.id = 123456
    testcase_dict = {
        'project_name':
            'test_proj',
        'job_type':
            'libfuzzer_asan_test_proj',
        'bug_information':
            '999',
        'crash_type':
            'Heap-buffer-overflow',
        'crash_state':
            'Foo::Bar',
        'timestamp':
            datetime.datetime(2024, 1, 1, 0, 0, 0),
        'regression':
            '10:20',
        'fixed':
            '30:40',
        'additional_metadata':
            json.dumps({'fuzzer_binary_name': 'fuzz_target_1'}),
        'security_flag':
            True,
        'security_severity':
            1,
    }
    mock_testcase.__getitem__.side_effect = lambda key: testcase_dict[key]
    mock_testcase.get.side_effect = lambda key, default=None: testcase_dict.get(
        key, default)

    self.syncer.get_oss_fuzz_testcase = mock.MagicMock(
        return_value=mock_testcase)
    self.syncer.has_analyzed_regression = mock.MagicMock(return_value=False)
    self.syncer.has_analyzed_fixed = mock.MagicMock(return_value=False)

    issue = {'issueId': '999', 'issueState': {'status': 'FIXED'}}
    self.syncer.process_issue(issue)

    self.assertEqual(2, self.mock_publisher.publish.call_count)

    # First call: regressed
    call1 = self.mock_publisher.publish.call_args_list[0]
    self.assertEqual('projects/test-osv-project/topics/tasks', call1[0][0])
    self.assertEqual('regressed', call1[1]['type'])
    self.assertEqual('oss-fuzz:123456', call1[1]['source_id'])
    self.assertEqual('123456', call1[1]['testcase_id'])
    self.assertEqual('test_proj', call1[1]['project_name'])
    self.assertEqual('x86_64', call1[1]['architecture'])
    self.assertEqual('address', call1[1]['sanitizer'])
    self.assertEqual('fuzz_target_1', call1[1]['fuzz_target'])
    self.assertEqual('regress_old', call1[1]['old_commit'])
    self.assertEqual('regress_new', call1[1]['new_commit'])
    self.assertEqual('High', call1[1]['severity'])

    # Second call: fixed
    call2 = self.mock_publisher.publish.call_args_list[1]
    self.assertEqual('fixed', call2[1]['type'])
    self.assertEqual('oss-fuzz:123456', call2[1]['source_id'])
    self.assertEqual('123456', call2[1]['testcase_id'])
    self.assertEqual('fix_old', call2[1]['old_commit'])
    self.assertEqual('fix_new', call2[1]['new_commit'])

  def test_process_issue_already_analyzed(self):
    """Test process_issue skips already analyzed issues."""
    mock_testcase = mock.MagicMock()
    mock_testcase.key.id = 123456
    self.syncer.get_oss_fuzz_testcase = mock.MagicMock(
        return_value=mock_testcase)
    self.syncer.has_analyzed_regression = mock.MagicMock(return_value=True)
    self.syncer.has_analyzed_fixed = mock.MagicMock(return_value=True)

    issue = {'issueId': '999', 'issueState': {'status': 'FIXED'}}
    self.syncer.process_issue(issue)

    self.mock_publisher.publish.assert_not_called()


if __name__ == '__main__':
  unittest.main()
