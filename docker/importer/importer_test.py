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
import http.server
import threading

from unittest import mock
import warnings

from google.cloud import ndb
import pygit2
from docker.mock_test_handler import MockDataHandler
import importer
import osv
from osv import tests

TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')
TEST_BUCKET = 'test-osv-source-bucket'

_MIN_VALID_VULNERABILITY = '''{
   "id":"OSV-2017-134",
   "modified":"2021-01-01T00:00:00Z",
   "schema_version":"1.3.0",
}'''

_MIN_INVALID_VULNERABILITY = '''{
   "id":"OSV-2017-145",
   "schema_version":"1.3.0",
}'''
PORT = 8888
SERVER_ADDRESS = ('localhost', PORT)


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

    self.tasks_topic = f'projects/{tests.TEST_PROJECT_ID}/topics/tasks'

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_basic(self, unused_mock_time: mock.MagicMock,
                 mock_publish: mock.MagicMock):
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
            'score': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L',
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

    self.mock_repo.add_file('2021-111.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
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
            self.tasks_topic,
            data=b'',
            deleted='false',
            original_sha256=('874535768a62eb9dc4f3ea7acd9a4601'
                             '19a3cd03fc15360bf16187f54df92a75'),
            path='2021-111.yaml',
            source='oss-fuzz',
            type='update',
            req_timestamp='12345')
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
  def test_invalid(self, mock_publish: mock.MagicMock):
    """Test invalid entries behaves correctly."""
    self.mock_repo.add_file('2021-111.yaml', _MIN_INVALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
    with self.assertLogs(level='WARNING') as logs:
      imp.run()
    self.assertEqual(3, len(logs.output))
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0])
    self.assertIn('WARNING:root:Invalid data:', logs.output[1])
    self.assertIn(
        "ERROR:root:Failed to parse 2021-111.yaml: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2])

    mock_publish.assert_not_called()
    bucket = self.mock_storage_client().bucket(
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET)
    expected_log = bucket.blob().upload_from_string.call_args[0][0]
    self.assertIn('Failed to parse vulnerability', expected_log)

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_nop(self, mock_publish: mock.MagicMock):
    """Test deletion."""
    self.mock_repo.add_file('2021-111.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    repo = pygit2.Repository(self.remote_source_repo_path)
    synced_commit = repo.head.peel()

    self.source_repo.last_synced_hash = str(synced_commit.id)
    self.source_repo.put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
    imp.run()

    mock_publish.assert_not_called()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_scheduled_updates(self, unused_mock_time: mock.MagicMock,
                             mock_publish: mock.MagicMock):
    """Test scheduled updates."""
    self.mock_repo.add_file('proj/OSV-2021-1337.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.add_file('proj/OSV-2021-1339.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.add_file('OSV-2021-1338.yaml', _MIN_VALID_VULNERABILITY)
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
                        repo_url='https://example.com/some/repo',
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
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
    imp.run()

    mock_publish.assert_has_calls([
        mock.call(
            self.tasks_topic,
            data=b'',
            deleted='false',
            original_sha256=('874535768a62eb9dc4f3ea7acd9a4601'
                             '19a3cd03fc15360bf16187f54df92a75'),
            path='proj/OSV-2021-1337.yaml',
            source='oss-fuzz',
            type='update',
            req_timestamp='12345'),
        mock.call(
            self.tasks_topic,
            allocated_id='OSV-2021-1339',
            data=b'',
            source_id='oss-fuzz:124',
            type='impact',
            req_timestamp='12345'),
    ])

    source_repo = osv.SourceRepository.get_by_id('oss-fuzz')
    self.assertEqual(
        datetime.datetime(2021, 1, 1, 10, 0), source_repo.last_update_date)

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_scheduled_updates_already_done(self, mock_publish):  # pylint: disable=unused-argument
    """Scheduled updates already done."""
    # TODO(michaelkedar): This test doesn't check anything
    self.skipTest("Not Implemented")
    source_repo = osv.SourceRepository.get_by_id('oss-fuzz')
    source_repo.last_update_date = importer.utcnow()
    source_repo.put()

    self.mock_repo.add_file('proj/OSV-2021-1337.yaml', _MIN_VALID_VULNERABILITY)
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
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
    imp.run()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_no_updates(self, mock_publish):  # pylint: disable=unused-argument
    """Test no update marker."""
    # TODO(michaelkedar): This test doesn't check anything
    self.skipTest("Not Implemented")
    self.mock_repo.add_file('2021-111.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email', 'message. OSV-NO-UPDATE')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
    imp.run()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_ignore(self, mock_publish):  # pylint: disable=unused-argument
    """Test ignoring."""
    # TODO(michaelkedar): This test doesn't check anything
    self.skipTest("Not Implemented")
    self.mock_repo.add_file('2021-111IGNORE.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email', 'message.')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
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

    self.tasks_topic = f'projects/{tests.TEST_PROJECT_ID}/topics/tasks'

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @mock.patch('google.cloud.storage.Blob.upload_from_string')
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_bucket(self, unused_mock_time: mock.MagicMock,
                  mock_publish: mock.MagicMock,
                  upload_from_str: mock.MagicMock):
    """Test bucket updates."""
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)

    with self.assertLogs(level='WARNING') as logs:
      imp.run()
    self.assertEqual(3, len(logs.output))
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0])
    self.assertIn('WARNING:root:Invalid data:', logs.output[1])
    self.assertIn(
        "ERROR:root:Failed to parse vulnerability a/b/test-invalid.json: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2])

    mock_publish.assert_has_calls([
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='bucket',
            path='a/b/android-test.json',
            original_sha256=('12453f85cd87bc1d465e0d013db572c0'
                             '1f7fb7de3b3a33de94ebcc7bd0f23a14'),
            deleted='false',
            req_timestamp='12345'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='bucket',
            path='a/b/test.json',
            original_sha256=('62966a80f6f9f54161803211069216177'
                             '37340a47f43356ee4a1cabe8f089869'),
            deleted='false',
            req_timestamp='12345'),
    ])

    # Test this entry is not published
    dsa_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='bucket',
        path='a/b/DSA-3029-1.json',
        original_sha256=mock.ANY,
        deleted='false')
    self.assertNotIn(dsa_call, mock_publish.mock_calls)

    # Test invalid entry is not published
    invalid_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='bucket',
        path='a/b/test-invalid.json',
        original_sha256=mock.ANY,
        deleted=mock.ANY)
    self.assertNotIn(invalid_call, mock_publish.mock_calls)
    # Check if uploaded log str has the failed to parse vuln
    self.assertTrue(
        any('Failed to parse vulnerability "a/b/test-invalid.json"' in x[0][0]
            for x in upload_from_str.call_args_list))

  @mock.patch('google.cloud.storage.Blob.upload_from_string')
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_import_override(self, unused_mock_time: mock.MagicMock,
                           mock_publish: mock.MagicMock,
                           upload_from_str: mock.MagicMock):
    """Test bucket updates."""

    self.source_repo.ignore_last_import_time = True
    self.source_repo.put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)

    imp.run()  # TODO(michaelkedar): Why does this run not generate logs?

    mock_publish.assert_has_calls([
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='bucket',
            path='a/b/DSA-3029-1.json',
            original_sha256=mock.ANY,
            deleted='false',
            req_timestamp='12345')
    ])
    mock_publish.reset_mock()

    # Second run should not import it again, since each import run resets the
    # value of source_repo.ignore_last_import_time to False
    with self.assertLogs(level='WARNING') as logs:
      imp.run()
    self.assertEqual(3, len(logs.output))
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0])
    self.assertIn('WARNING:root:Invalid data:', logs.output[1])
    self.assertIn(
        "ERROR:root:Failed to parse vulnerability a/b/test-invalid.json: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2])

    dsa_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='bucket',
        path='a/b/DSA-3029-1.json',
        original_sha256=mock.ANY,
        deleted='false',
        req_timestamp='12345')
    self.assertNotIn(dsa_call, mock_publish.mock_calls)
    # Check if uploaded log str has the failed to parse vuln
    self.assertTrue(
        any('Failed to parse vulnerability "a/b/test-invalid.json"' in x[0][0]
            for x in upload_from_str.call_args_list))


@mock.patch('importer.utcnow', lambda: datetime.datetime(2024, 1, 1))
class RESTImporterTest(unittest.TestCase):
  """REST importer tests."""
  httpd = None

  def setUp(self):
    tests.reset_emulator()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)
    self.mock_repo = tests.mock_repository(self)
    warnings.filterwarnings("ignore", "unclosed", ResourceWarning)

    storage_patcher = mock.patch('google.cloud.storage.Client')
    self.addCleanup(storage_patcher.stop)
    self.mock_storage_client = storage_patcher.start()

    self.remote_source_repo_path = self.mock_repo.path
    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.REST_ENDPOINT,
        id='curl',
        name='curl',
        repo_url=f'http://{SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}',
        rest_api_url=f'http://{SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}/',
        db_prefix='CURL-',
        editable=False)
    self.source_repo.put()
    self.tasks_topic = f'projects/{tests.TEST_PROJECT_ID}/topics/tasks'

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)
    self.httpd.shutdown()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_basic(self, unused_mock_time: mock.MagicMock,
                 mock_publish: mock.MagicMock):
    "Testing basic rest endpoint import"
    self.httpd = http.server.HTTPServer(SERVER_ADDRESS, MockDataHandler)
    thread = threading.Thread(target=self.httpd.serve_forever)
    thread.start()
    self.source_repo.last_update_date = datetime.datetime(2020, 1, 1)
    self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False)
    imp.run()
    mock_publish.assert_called()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_time(self, unused_mock_time: mock.MagicMock,
                mock_publish: mock.MagicMock):
    """Testing none last modified"""

    MockDataHandler.last_modified = 'Fri, 01 Jan 2021 00:00:00 GMT'
    self.httpd = http.server.HTTPServer(SERVER_ADDRESS, MockDataHandler)
    thread = threading.Thread(target=self.httpd.serve_forever)
    thread.start()
    self.source_repo.last_update_date = datetime.datetime(2024, 1, 1)
    self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True)
    imp.run()
    mock_publish.assert_not_called()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_dates_between(self, unused_mock_time: mock.MagicMock,
                         mock_publish: mock.MagicMock):
    "Testing from date in between entries"
    self.httpd = http.server.HTTPServer(SERVER_ADDRESS, MockDataHandler)
    thread = threading.Thread(target=self.httpd.serve_forever)
    thread.start()
    self.source_repo.last_update_date = datetime.datetime(2023, 6, 6)
    self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False)
    imp.run()
    mock_publish.assert_called()


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
