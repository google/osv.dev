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
"""Importer tests."""
import datetime
import os
import shutil
import tempfile
import unittest
from unittest import mock

from google.cloud import ndb
import pygit2

import importer
import osv
from osv import tests

TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')
TEST_BUCKET = 'test-osv-source-bucket'

_EMPTY_VULNERABILITY = 'id: EMPTY'


@mock.patch('importer.utcnow', lambda: datetime.datetime(2021, 1, 1))
class ImporterTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Importer tests."""

  def _load_test_data(self, name):
    """Load test data."""
    with open(os.path.join(TEST_DATA_DIR, name)) as f:
      return f.read()

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)
    self.mock_repo = tests.mock_repository(self)

    storage_patcher = mock.patch('google.cloud.storage.Client')
    self.addCleanup(storage_patcher.stop)
    self.mock_storage_client = storage_patcher.start()

    self.remote_source_repo_path = self.mock_repo.path
    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.GIT,
        id='oss-fuzz',
        name='oss-fuzz',
        db_prefix='OSV-',
        repo_url='file://' + self.remote_source_repo_path,
        repo_username='',
        ignore_patterns=['.*IGNORE.*'])
    self.source_repo.put()

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_basic(self, mock_publish):
    """Test basic run."""
    osv.Bug(
        db_id='OSV-2017-134',
        affected_packages=[{
            'versions': ['FILE5_29', 'FILE5_30'],
            'ranges': [{
                'type':
                    'GIT',
                'repo_url':
                    'https://github.com/file/file.git',
                'events': [
                    {
                        'type': 'introduced',
                        'value': '17ee4cf670c363de8d2ea4a4897d7a699837873f'
                    },
                    {
                        'type': 'fixed',
                        'value': '19ccebafb7663c422c714e0c67fa4775abf91c43'
                    },
                ],
            }],
            'package': {
                'ecosystem': 'OSS-Fuzz',
                'name': 'file',
                'purl': 'pkg:generic/file',
            },
            'ecosystem_specific': {
                'severity': 'MEDIUM',
            },
            'database_specific': {
                'database_specific': 1337,
            },
        }],
        affected_fuzzy=['5-29', '5-30'],
        credits=[{
            'name': 'Foo bar',
            'contact': [],
        }, {
            'name': 'Bar foo',
            'contact': ['mailto:bar@foo.com'],
        }],
        severities=[{
            'type': 'CVSS_V3',
            'score': '7.5',
        }],
        details=(
            'OSS-Fuzz report: '
            'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1064\n\n'
            'Crash type: Heap-buffer-overflow READ 1\n'
            'Crash state:\ncdf_file_property_info\ncdf_file_summary_info\n'
            'cdf_check_summary_info\n'),
        fixed='19ccebafb7663c422c714e0c67fa4775abf91c43',
        has_affected=True,
        issue_id='1064',
        public=True,
        reference_url_types={
            'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=1064':
                'REPORT'
        },
        regressed='17ee4cf670c363de8d2ea4a4897d7a699837873f',
        search_indices=['file', '2017-134', '2017', '134'],
        source_id='oss-fuzz:5417710252982272',
        source_of_truth=osv.SourceOfTruth.INTERNAL,
        status=1,
        summary='Heap-buffer-overflow in cdf_file_property_info',
        timestamp=datetime.datetime(2021, 1, 15, 0, 0, 24, 559102),
        database_specific={
            'database_specific': 1337
        },
    ).put()

    self.mock_repo.add_file('2021-111.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')
    imp.run()

    repo = pygit2.Repository(self.remote_source_repo_path)
    commit = repo.head.peel()

    self.assertEqual('infra@osv.dev', commit.author.email)
    self.assertEqual('OSV', commit.author.name)
    self.assertEqual('Import from OSS-Fuzz', commit.message)
    diff = repo.diff(commit.parents[0], commit)
    self.expect_equal('diff_basic', diff.patch)

    mock_publish.assert_has_calls([
        mock.call(
            'projects/oss-vdb/topics/tasks',
            data=b'',
            deleted='false',
            original_sha256=('bd3cc48676794308a58a19c97972a5e5'
                             '42abcc9eb948db5701421616432cc0b9'),
            path='2021-111.yaml',
            source='oss-fuzz',
            type='update')
    ])
    bug = osv.Bug.get_by_id('OSV-2017-134')
    self.assertEqual(osv.SourceOfTruth.SOURCE_REPO, bug.source_of_truth)

    source_repo = osv.SourceRepository.get_by_id('oss-fuzz')
    self.assertEqual(str(commit.id), source_repo.last_synced_hash)

    self.mock_storage_client().get_bucket.assert_called_with('bucket')
    bucket = self.mock_storage_client().get_bucket('bucket')

    expected_json = bucket.blob().upload_from_string.call_args[0][0]
    self.expect_equal('expected.json', expected_json)

    bucket.blob.assert_has_calls([
        mock.call('testcase/5417710252982272.json'),
        mock.call().upload_from_string(expected_json),
        mock.call('issue/1064.json'),
        mock.call().upload_from_string(expected_json),
    ])

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_delete(self, mock_publish):
    """Test deletion."""
    self.mock_repo.add_file('2021-111.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    repo = pygit2.Repository(self.remote_source_repo_path)
    synced_commit = repo.head.peel()

    self.source_repo.last_synced_hash = str(synced_commit.id)
    self.source_repo.put()

    self.mock_repo.delete_file('2021-111.yaml')
    self.mock_repo.commit('User', 'user@email')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')
    imp.run()

    mock_publish.assert_has_calls([
        mock.call(
            'projects/oss-vdb/topics/tasks',
            data=b'',
            deleted='true',
            original_sha256='',
            path='2021-111.yaml',
            source='oss-fuzz',
            type='update')
    ])

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_scheduled_updates(self, mock_publish):
    """Test scheduled updates."""
    self.mock_repo.add_file('proj/OSV-2021-1337.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.add_file('proj/OSV-2021-1339.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.add_file('OSV-2021-1338.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.commit('OSV', 'infra@osv.dev')

    osv.SourceRepository(
        type=osv.SourceRepositoryType.GIT,
        id='source',
        name='source',
        repo_url='file://' + self.remote_source_repo_path,
        repo_username='').put()
    osv.Bug(
        db_id='OSV-2021-1337',
        affected_packages=[
            osv.AffectedPackage(
                package=osv.Package(ecosystem='OSS-Fuzz', name='proj'))
        ],
        status=1,
        source_id='oss-fuzz:123',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
        timestamp=datetime.datetime(2020, 1, 1, 0, 0, 0, 0)).put()
    osv.Bug(
        db_id='OSV-2021-1338',
        affected_packages=[
            osv.AffectedPackage(
                package=osv.Package(ecosystem='ecosystem', name='proj'),
                ranges=[
                    osv.AffectedRange2(
                        type='GIT',
                        events=[
                            osv.AffectedEvent(type='introduced', value='0'),
                            osv.AffectedEvent(type='fixed', value='fix'),
                        ])
                ])
        ],
        source_id='source:OSV-2021-1338.yaml',
        status=1,
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
        timestamp=importer.utcnow()).put()
    osv.Bug(
        db_id='OSV-2021-1339',
        affected_packages=[
            osv.AffectedPackage(
                package=osv.Package(ecosystem='OSS-Fuzz', name='proj'))
        ],
        status=1,
        source_id='oss-fuzz:124',
        source_of_truth=osv.SourceOfTruth.INTERNAL,
        timestamp=datetime.datetime(2020, 1, 1, 0, 0, 0, 0)).put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')
    imp.run()

    mock_publish.assert_has_calls([
        mock.call(
            'projects/oss-vdb/topics/tasks',
            data=b'',
            deleted='false',
            original_sha256=('bd3cc48676794308a58a19c97972a5e5'
                             '42abcc9eb948db5701421616432cc0b9'),
            path='proj/OSV-2021-1337.yaml',
            source='oss-fuzz',
            type='update'),
        mock.call(
            'projects/oss-vdb/topics/tasks',
            allocated_id='OSV-2021-1339',
            data=b'',
            source_id='oss-fuzz:124',
            type='impact'),
    ])

    source_repo = osv.SourceRepository.get_by_id('oss-fuzz')
    self.assertEqual(datetime.date(2021, 1, 1), source_repo.last_update_date)

  def test_scheduled_updates_already_done(self):
    """Scheduled updates already done."""
    source_repo = osv.SourceRepository.get_by_id('oss-fuzz')
    source_repo.last_update_date = importer.utcnow().date()
    source_repo.put()

    self.mock_repo.add_file('proj/OSV-2021-1337.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.commit('OSV', 'infra@osv.dev')
    osv.Bug(
        db_id='OSV-2021-1337',
        project=['proj'],
        fixed='',
        status=1,
        source_id='oss-fuzz:123',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
        timestamp=datetime.datetime(2020, 1, 1, 0, 0, 0, 0)).put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')
    imp.run()

  def test_no_updates(self):
    """Test no update marker."""
    self.mock_repo.add_file('2021-111.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email', 'message. OSV-NO-UPDATE')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')
    imp.run()

  def test_ignore(self):
    """Test ignoring."""
    self.mock_repo.add_file('2021-111IGNORE.yaml', _EMPTY_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email', 'message.')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')
    imp.run()


@mock.patch('importer.utcnow', lambda: datetime.datetime(2021, 1, 1))
class BucketImporterTest(unittest.TestCase):
  """Bucket importer tests."""

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.BUCKET,
        id='bucket',
        name='bucket',
        bucket=TEST_BUCKET,
        extension='.json')
    self.source_repo.put()

    osv.Bug(
        id='DSA-3029-1',
        db_id='DSA-3029-1',
        status=1,
        source='test',
        public=True,
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:7',
                'name': 'test',
            },
        }],
        # Same timestamp as the DSA-3029-1 modified file
        import_last_modified=datetime.datetime(2014, 9, 20, 8, 18, 7, 0),
    ).put()

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_bucket(self, mock_publish: mock.MagicMock):
    """Test bucket updates."""

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')

    imp.run()
    mock_publish.assert_has_calls([
        mock.call(
            'projects/oss-vdb/topics/tasks',
            data=b'',
            type='update',
            source='bucket',
            path='a/b/test.json',
            original_sha256=('b2b37bde8f39256239419078de672ce7'
                             'a408735f1c2502ee8fa08745096e1971'),
            deleted='false'),
    ])

    # Test this entry is not published
    dsa_call = mock.call(
        'projects/oss-vdb/topics/tasks',
        data=b'',
        type='update',
        source='bucket',
        path='a/b/DSA-3029-1.json',
        original_sha256=mock.ANY,
        deleted='false')
    assert dsa_call not in mock_publish.mock_calls

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_import_override(self, mock_publish: mock.MagicMock):
    """Test bucket updates."""

    self.source_repo.ignore_last_import_time = True
    self.source_repo.put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            'bucket')

    imp.run()

    mock_publish.assert_has_calls([
        mock.call(
            'projects/oss-vdb/topics/tasks',
            data=b'',
            type='update',
            source='bucket',
            path='a/b/DSA-3029-1.json',
            original_sha256=mock.ANY,
            deleted='false')
    ])
    mock_publish.reset_mock()

    # Second run should not import it again, since each import run resets the
    # value of source_repo.ignore_last_import_time to False
    imp.run()

    dsa_call = mock.call(
        'projects/oss-vdb/topics/tasks',
        data=b'',
        type='update',
        source='bucket',
        path='a/b/DSA-3029-1.json',
        original_sha256=mock.ANY,
        deleted='false')
    assert dsa_call not in mock_publish.mock_calls


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
