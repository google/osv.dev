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
import contextlib
import datetime
import os
import shutil
import tempfile
import unittest
import http.server
import logging
import threading

from unittest import mock
from urllib3.exceptions import SystemTimeWarning
import warnings

from google.cloud import ndb
from google.cloud import storage
from google.cloud.storage import retry
import pygit2
from gcp.workers.mock_test.mock_test_handler import MockDataHandler
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
MOCK_ADDRESS_FORMAT = f"http://{SERVER_ADDRESS[0]}:{SERVER_ADDRESS[1]}/"


@mock.patch('importer.utcnow',
            lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC))
class ImporterTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Importer tests."""

  def _load_test_data(self, name):
    """Load test data."""
    with open(os.path.join(TEST_DATA_DIR, name)) as f:
      return f.read()

  @classmethod
  def setUpClass(cls):
    # Start the emulator BEFORE creating the ndb client
    cls.emulator = cls.enterClassContext(tests.datastore_emulator())
    cls.enterClassContext(ndb.Client().context(cache_policy=False))

  def setUp(self):
    self.emulator.reset()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)
    warnings.filterwarnings('ignore', category=SystemTimeWarning)
    self.mock_repo = tests.mock_repository(self)

    storage_patcher = mock.patch('google.cloud.storage.Client')
    self.addCleanup(storage_patcher.stop)
    self.mock_storage_client = storage_patcher.start()

    self.remote_source_repo_path = self.mock_repo.path
    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.GIT,
        id='oss-fuzz',
        name='oss-fuzz',
        db_prefix=['OSV-'],
        repo_url='file://' + self.remote_source_repo_path,
        repo_username='',
        ignore_patterns=['.*IGNORE.*'],
        strict_validation=True)
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
        timestamp=datetime.datetime(
            2021, 1, 15, 0, 0, 24, 559102, tzinfo=datetime.UTC),
        database_specific={
            'database_specific': 1337
        },
    ).put()

    self.mock_repo.add_file('2021-111.yaml', _MIN_VALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)
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
            type='update-oss-fuzz',
            req_timestamp='12345',
            src_timestamp='')
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
        mock.call().upload_from_string(
            expected_json, retry=retry.DEFAULT_RETRY),
        mock.call('issue/1064.json'),
        mock.call().upload_from_string(
            expected_json, retry=retry.DEFAULT_RETRY),
    ])

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_invalid(self, mock_publish: mock.MagicMock):
    """Test invalid entries behaves correctly."""
    self.mock_repo.add_file('2021-111.yaml', _MIN_INVALID_VULNERABILITY)
    self.mock_repo.commit('User', 'user@email')

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)
    with self.assertLogs(level='WARNING') as logs:
      imp.run()

    self.assertIn(
        osv.ImportFinding(
            bug_id='OSV-2017-145',
            source='oss-fuzz',
            findings=[osv.ImportFindings.INVALID_JSON],
            first_seen=importer.utcnow(),
            last_attempt=importer.utcnow()).to_dict(),
        [r.to_dict() for r in osv.ImportFinding.query()])

    self.assertEqual(
        5,
        len(logs.output),
        msg='Expected number of WARNING level (or higher) logs not found')
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
                            True, False)
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
        repo_username='',
        strict_validation=True).put()
    osv.Bug(
        db_id='OSV-2021-1337',
        affected_packages=[
            osv.AffectedPackage(
                package=osv.Package(ecosystem='OSS-Fuzz', name='proj'))
        ],
        status=1,
        source_id='oss-fuzz:123',
        source_of_truth=osv.SourceOfTruth.SOURCE_REPO,
        timestamp=datetime.datetime(
            2020, 1, 1, 0, 0, 0, 0, tzinfo=datetime.UTC)).put()
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
        timestamp=datetime.datetime(
            2020, 1, 1, 0, 0, 0, 0, tzinfo=datetime.UTC)).put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)
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
            type='update-oss-fuzz',
            req_timestamp='12345',
            src_timestamp=''),
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
        datetime.datetime(2021, 1, 1, 10, 0, tzinfo=datetime.UTC),
        source_repo.last_update_date)

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
        timestamp=datetime.datetime(
            2020, 1, 1, 0, 0, 0, 0, tzinfo=datetime.UTC)).put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)
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
                            True, False)
    imp.run()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_ignore(self, mock_publish):  # pylint: disable=unused-argument
    """Test ignoring."""
    self.assertTrue(self.source_repo.ignore_file('/tmp/foo/recoredIGNOREme'))
    source_repo_ignore_negative = osv.SourceRepository(
        ignore_patterns=['(^(?!USN-).*$)'])
    self.assertTrue(
        source_repo_ignore_negative.ignore_file('/tmp/foo/CVE-2024-1234.json'))
    source_repo_ignore_multiple = osv.SourceRepository(
        ignore_patterns=['^(?!MAL-).*$', 'MAL-0000.*'])
    self.assertTrue(
        source_repo_ignore_multiple.ignore_file('/tmp/foo/CVE-2024-1234.json'))
    self.assertTrue(
        source_repo_ignore_multiple.ignore_file('/tmp/foo/MAL-0000-0001.json'))

  @mock.patch('osv.repos.FETCH_CACHE_SECONDS', 0)
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_importer_bug_creation_and_update_git(self, mock_publish):
    """Test importer bug creation and updates via Git."""
    self.skipTest('disabled')
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)

    # 1. Start with bug not in db.
    test_id = 'OSV-TEST-GIT-1'
    self.assertIsNone(osv.Bug.get_by_id(test_id))

    # 2. Run importer for one Git record.
    vuln_v1 = f'''
id: {test_id}
modified: '2023-01-01T00:00:00Z'
schema_version: '1.3.0'
summary: Summary v1
affected:
- package:
    name: package-a
    ecosystem: PyPI
  versions:
  - 1.0.0
'''
    self.mock_repo.add_file(f'{test_id}.yaml', vuln_v1)
    self.mock_repo.commit('User', 'user@email')
    imp.run()

    # 3. Check that record is now in db.
    mock_publish.assert_called_once()
    bug_v1 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v1)
    self.assertEqual('Summary v1', bug_v1.summary)
    self.assertEqual(1, len(bug_v1.affected_packages))
    self.assertEqual('package-a', bug_v1.affected_packages[0].package.name)
    self.assertIsNotNone(bug_v1.affected_checksum)
    v1_checksum = bug_v1.affected_checksum

    mock_publish.reset_mock()

    # 4. Rerun import for record w/ modified affected[].
    vuln_v2 = f'''
id: {test_id}
modified: '2023-01-02T00:00:00Z'
schema_version: '1.3.0'
summary: Summary v1
affected:
- package:
    name: package-b
    ecosystem: PyPI
  versions:
  - 2.0.0
'''
    self.mock_repo.add_file(f'{test_id}.yaml', vuln_v2)
    self.mock_repo.commit('User', 'user@email')
    imp.run()

    # 5. Check that modified affected now in datastore.
    mock_publish.assert_called_once()
    bug_v2 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v2)
    self.assertEqual('Summary v1', bug_v2.summary)
    self.assertEqual(1, len(bug_v2.affected_packages))
    self.assertEqual('package-b', bug_v2.affected_packages[0].package.name)
    self.assertNotEqual(v1_checksum, bug_v2.affected_checksum)
    v2_checksum = bug_v2.affected_checksum

    mock_publish.reset_mock()

    # 6. Manually modify the Bug.affected (to pretend it's been enriched).
    enriched_package = osv.AffectedPackage(
        package=osv.Package(name='package-b', ecosystem='PyPI'),
        ecosystem_specific={'extra_data': 'enriched'})
    bug_v2.affected_packages = [enriched_package]
    bug_v2.put()

    # 7. Rerun import for record w/ modified summary (but affected the same).
    vuln_v3 = f'''
id: {test_id}
modified: '2023-01-03T00:00:00Z'
schema_version: '1.3.0'
summary: Summary v3
affected:
- package:
    name: package-b
    ecosystem: PyPI
  versions:
  - 2.0.0
'''
    self.mock_repo.add_file(f'{test_id}.yaml', vuln_v3)
    self.mock_repo.commit('User', 'user@email')
    imp.run()

    # 8. Check that summary has been updated, but not affected.
    mock_publish.assert_called_once()
    bug_v3 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v3)
    self.assertEqual('Summary v3', bug_v3.summary)
    self.assertEqual(1, len(bug_v3.affected_packages))
    self.assertEqual('package-b', bug_v3.affected_packages[0].package.name)
    # This is the key check: the enriched data should still be there.
    self.assertEqual({'extra_data': 'enriched'},
                     bug_v3.affected_packages[0].ecosystem_specific)
    # The checksum should be the same as before enrichment, as it's based on
    # the raw vuln.
    self.assertEqual(v2_checksum, bug_v3.affected_checksum)


@mock.patch('importer.utcnow',
            lambda: datetime.datetime(2021, 1, 1, tzinfo=datetime.UTC))
class BucketImporterTest(unittest.TestCase):
  """GCS bucket importer tests."""

  @classmethod
  def setUpClass(cls):
    # Start the emulator BEFORE creating the ndb client
    cls.emulator = cls.enterClassContext(tests.datastore_emulator())
    cls.ndb_context = cls.enterClassContext(
        ndb.Client().context(cache_policy=False))

  def setUp(self):
    self.emulator.reset()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)
    warnings.filterwarnings('ignore', category=SystemTimeWarning)

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.BUCKET,
        id='test',
        name='test',
        bucket=TEST_BUCKET,
        directory_path='a/b',
        extension='.json',
        strict_validation=True)
    self.source_repo.put()

    # Preexisting Bug that exists in GCS.
    osv.Bug(
        id='DSA-3029-1',
        db_id='DSA-3029-1',
        status=1,
        source='test',
        source_id='test:a/b/DSA-3029-1.json',
        public=True,
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:7',
                'name': 'test',
            },
        }],
        # Same timestamp as the gs://TEST_BUCKET/a/b/DSA-3029-1.json modified
        # file
        import_last_modified=datetime.datetime(
            2014, 9, 20, 8, 18, 7, 0, tzinfo=datetime.UTC),
    ).put()

    # Preexisting Bug that does not exist in GCS.
    osv.Bug(
        id='CVE-2018-1000030',
        db_id='CVE-2018-1000030',
        status=1,
        source='test',
        source_id='test:a/b/CVE-2018-1000030.json',
        public=True,
        affected_packages=[{
            'package': {
                'ecosystem': '',
                'name': '',
                'purl': None,
            },
            'ranges': [{
                'events': [{
                    'value': '0',
                    'type': 'introduced'
                }, {
                    'value': '84471935ed2f62b8c5758fd544c7d37076fe0fa5',
                    'type': 'last_affected',
                }],
                "type": "GIT",
                "repo_url": "https://github.com/python/cpython"
            }]
        }],
        import_last_modified=datetime.datetime(
            2018, 2, 9, 3, 29, 0, 0, tzinfo=datetime.UTC),
    ).put()

    # Preexisting Bug (with a colon in the ID) that does not exist in GCS.
    osv.Bug(
        id='RXSA-2023:0101',
        db_id='RXSA-2023:0101',
        status=1,
        source='test',
        source_id='test:RXSA-2023:0101.json',
        public=True,
        affected_packages=[{
            'package': {
                'ecosystem':
                    'Rocky Linux:8',
                'name':
                    'kernel',
                'purl': ('pkg:rpm/rocky-linux/kernel'
                         '?distro=rocky-linux-8-sig-cloud&epoch=0'),
            },
            'ranges': [{
                'events': [{
                    'value': '0',
                    'type': 'introduced'
                }, {
                    'value': '0:4.18.0-425.10.1.el8_7.cloud',
                    'type': 'fixed'
                }],
                'type': 'ECOSYSTEM',
            }],
        }],
        import_last_modified=datetime.datetime(
            2018, 2, 9, 3, 29, 0, 0, tzinfo=datetime.UTC),
    ).put()

    self.tasks_topic = f'projects/{tests.TEST_PROJECT_ID}/topics/tasks'

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @mock.patch('google.cloud.storage.Blob.download_as_bytes')
  @mock.patch('google.cloud.storage.Client.list_blobs')
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_importer_bug_creation_and_update(self, mock_time, mock_publish,
                                            mock_list_blobs, mock_download):
    """Test importer bug creation and updates."""
    self.skipTest('disabled')
    del mock_time  # Unused.
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)

    # 1. Start with bug not in db.
    test_id = 'OSV-TEST-1'
    self.assertIsNone(osv.Bug.get_by_id(test_id))

    # 2. Run importer for one GCS record.
    vuln_v1 = f'''{{
       "id": "{test_id}",
       "modified": "2023-01-01T00:00:00Z",
       "schema_version": "1.3.0",
       "summary": "Summary v1",
       "affected": [
         {{
           "package": {{ "name": "package-a", "ecosystem": "PyPI" }},
           "versions": [ "1.0.0" ]
         }}
       ]
    }}'''

    mock_blob_v1 = mock.MagicMock(spec=storage.Blob)
    mock_blob_v1.name = f'a/b/{test_id}.json'
    mock_blob_v1.updated = datetime.datetime(
        2023, 1, 1, 0, 0, 1, tzinfo=datetime.UTC)

    mock_list_blobs.return_value = [mock_blob_v1]
    mock_download.return_value = vuln_v1.encode()

    imp.run()

    # 3. Check that record is now in db.
    mock_publish.assert_called_once()
    bug_v1 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v1)
    self.assertEqual('Summary v1', bug_v1.summary)
    self.assertEqual(1, len(bug_v1.affected_packages))
    self.assertEqual('package-a', bug_v1.affected_packages[0].package.name)
    self.assertIsNotNone(bug_v1.affected_checksum)
    v1_checksum = bug_v1.affected_checksum

    mock_publish.reset_mock()
    mock_list_blobs.reset_mock()
    mock_download.reset_mock()

    # 4. Rerun import for record w/ modified affected[].
    vuln_v2 = f'''{{
       "id": "{test_id}",
       "modified": "2023-01-02T00:00:00Z",
       "schema_version": "1.3.0",
       "summary": "Summary v1",
       "affected": [
         {{
           "package": {{ "name": "package-b", "ecosystem": "PyPI" }},
           "versions": [ "2.0.0" ]
         }}
       ]
    }}'''
    mock_blob_v2 = mock.MagicMock(spec=storage.Blob)
    mock_blob_v2.name = f'a/b/{test_id}.json'
    mock_blob_v2.updated = datetime.datetime(
        2023, 1, 2, 0, 0, 1, tzinfo=datetime.UTC)
    mock_list_blobs.return_value = [mock_blob_v2]
    mock_download.return_value = vuln_v2.encode()

    imp.run()

    # 5. Check that modified affected now in datastore.
    mock_publish.assert_called_once()
    bug_v2 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v2)
    self.assertEqual('Summary v1', bug_v2.summary)
    self.assertEqual(1, len(bug_v2.affected_packages))
    self.assertEqual('package-b', bug_v2.affected_packages[0].package.name)
    self.assertNotEqual(v1_checksum, bug_v2.affected_checksum)
    v2_checksum = bug_v2.affected_checksum

    mock_publish.reset_mock()
    mock_list_blobs.reset_mock()
    mock_download.reset_mock()

    # 6. Manually modify the Bug.affected (to pretend it's been enriched).
    enriched_package = osv.AffectedPackage(
        package=osv.Package(name='package-b', ecosystem='PyPI'),
        ecosystem_specific={'extra_data': 'enriched'})
    bug_v2.affected_packages = [enriched_package]
    bug_v2.put()

    # 7. Rerun import for record w/ modified summary (but affected the same).
    vuln_v3 = f'''{{
       "id": "{test_id}",
       "modified": "2023-01-03T00:00:00Z",
       "schema_version": "1.3.0",
       "summary": "Summary v3",
       "affected": [
         {{
           "package": {{ "name": "package-b", "ecosystem": "PyPI" }},
           "versions": [ "2.0.0" ]
         }}
       ]
    }}'''
    mock_blob_v3 = mock.MagicMock(spec=storage.Blob)
    mock_blob_v3.name = f'a/b/{test_id}.json'
    mock_blob_v3.updated = datetime.datetime(
        2023, 1, 3, 0, 0, 1, tzinfo=datetime.UTC)
    mock_list_blobs.return_value = [mock_blob_v3]
    mock_download.return_value = vuln_v3.encode()

    imp.run()

    # 8. Check that summary has been updated, but not affected.
    mock_publish.assert_called_once()
    bug_v3 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v3)
    self.assertEqual('Summary v3', bug_v3.summary)
    self.assertEqual(1, len(bug_v3.affected_packages))
    self.assertEqual('package-b', bug_v3.affected_packages[0].package.name)
    # This is the key check: the enriched data should still be there.
    self.assertEqual({'extra_data': 'enriched'},
                     bug_v3.affected_packages[0].ecosystem_specific)
    # The checksum should be the same as before enrichment, as it's based on
    # the raw vuln.
    self.assertEqual(v2_checksum, bug_v3.affected_checksum)


class BucketImporterMassDeletionTest(unittest.TestCase):
  """Rigorous deletion testing against production data (in staging)."""

  def setUp(self):
    if not (os.environ.get('CLOUD_BUILD') != 1 and
            'RUN_SLOW_TESTS' in os.environ):
      self.skipTest('Skipping slow test')
    # Note: This runs (non-destructively) against the real live (non-emulated)
    # staging datastore and GCS bucket.
    self.old_gcp = os.environ.get('GOOGLE_CLOUD_PROJECT')
    os.environ['GOOGLE_CLOUD_PROJECT'] = 'oss-vdb-test'
    self.enterContext(ndb.Client(project='oss-vdb-test').context())

    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    self.tasks_topic = f'projects/{tests.TEST_PROJECT_ID}/topics/tasks'

    # The live bucket in staging.
    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.BUCKET,
        id='cve-osv',
        name='cve-osv',
        bucket='osv-test-cve-osv-conversion',
        directory_path='osv-output',
        extension='.json',
        db_prefix=['CVE-'])

    tests.mock_datetime(self)

    self.logger = logging.getLogger()
    self.logger.level = logging.INFO

  def tearDown(self):
    if self.old_gcp is None:
      os.environ.pop('GOOGLE_CLOUD_PROJECT')
    else:
      os.environ['GOOGLE_CLOUD_PROJECT'] = self.old_gcp
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @mock.patch('google.cloud.storage.Blob.upload_from_string')
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  def test_deletions_in_staging(self, mock_publish: mock.MagicMock,
                                unused_upload_from_str: mock.MagicMock):
    """Load test against staging bucket and (non-emulated) staging Datastore."""
    imp = importer.Importer(
        'fake_public_key',
        'fake_private_key',
        self.tmp_dir,
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET,
        'bucket',
        True,
        False,
        deletion_safety_threshold_pct=100)

    imp.process_deletions(self.source_repo)
    # This will start to fail once relevant records are actually deleted out of
    # Datastore in staging.
    mock_publish.assert_has_calls([
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='cve-osv',
            path=mock.ANY,
            original_sha256=mock.ANY,
            deleted='true',
            req_timestamp=mock.ANY)
    ])


@mock.patch('importer.utcnow',
            lambda: datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
class RESTImporterTest(unittest.TestCase):
  """REST importer tests."""
  httpd = None

  @classmethod
  def setUpClass(cls):
    # Start the emulator BEFORE creating the ndb client
    cls.emulator = cls.enterClassContext(tests.datastore_emulator())
    cls.enterClassContext(ndb.Client().context(cache_policy=False))

  def setUp(self):
    self.emulator.reset()
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)
    warnings.filterwarnings('ignore', category=SystemTimeWarning)

    storage_patcher = mock.patch('google.cloud.storage.Client')
    self.addCleanup(storage_patcher.stop)
    self.mock_storage_client = storage_patcher.start()

    self.source_repo = osv.SourceRepository(
        type=osv.SourceRepositoryType.REST_ENDPOINT,
        id='curl',
        name='curl',
        link=MOCK_ADDRESS_FORMAT,
        rest_api_url=MOCK_ADDRESS_FORMAT,
        db_prefix=['CURL-', 'RHSA-', 'OSV-'],
        extension='.json',
        editable=False,
        strict_validation=True)
    self.source_repo.put()
    self.tasks_topic = f'projects/{tests.TEST_PROJECT_ID}/topics/tasks'

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  @contextlib.contextmanager
  def server(self, handler_class):
    """REST mock server context manager."""
    httpd = http.server.HTTPServer(SERVER_ADDRESS, handler_class)
    thread = threading.Thread(target=httpd.serve_forever)
    thread.start()
    try:
      yield httpd
    finally:
      httpd.shutdown()
      httpd.server_close()
      thread.join()

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_invalid(self, unused_mock_time: mock.MagicMock,
                   mock_publish: mock.MagicMock):
    """Test invalid records are treated correctly."""
    # TODO(apollock): implement

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_importer_bug_creation_and_update_rest(self, unused_mock_time,
                                                 mock_publish):
    """Test importer bug creation and updates via REST."""
    self.skipTest('disabled')
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False, False)

    # 1. Start with bug not in db.
    test_id = 'OSV-TEST-REST-1'
    self.assertIsNone(osv.Bug.get_by_id(test_id))

    # 2. Run importer for one REST record.
    vuln_v1 = f'''[{{
       "id": "{test_id}",
       "modified": "2023-01-01T00:00:00Z",
       "schema_version": "1.3.0",
       "summary": "Summary v1",
       "affected": [
         {{
           "package": {{ "name": "package-a", "ecosystem": "PyPI" }},
           "versions": [ "1.0.0" ]
         }}
       ]
    }}]'''
    data_handler = MockDataHandler
    data_handler.last_modified = 'Mon, 01 Jan 2023 00:00:00 GMT'
    data_handler.load_data(data_handler, vuln_v1)

    with self.server(data_handler):
      imp.run()

    # 3. Check that record is now in db.
    mock_publish.assert_called_once()
    bug_v1 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v1)
    self.assertEqual('Summary v1', bug_v1.summary)
    self.assertEqual(1, len(bug_v1.affected_packages))
    self.assertEqual('package-a', bug_v1.affected_packages[0].package.name)
    self.assertIsNotNone(bug_v1.affected_checksum)
    v1_checksum = bug_v1.affected_checksum

    mock_publish.reset_mock()

    # 4. Rerun import for record w/ modified affected[].
    vuln_v2 = f'''[{{
       "id": "{test_id}",
       "modified": "2023-01-02T00:00:00Z",
       "schema_version": "1.3.0",
       "summary": "Summary v1",
       "affected": [
         {{
           "package": {{ "name": "package-b", "ecosystem": "PyPI" }},
           "versions": [ "2.0.0" ]
         }}
       ]
    }}]'''
    data_handler.last_modified = 'Mon, 02 Jan 2023 00:00:00 GMT'
    data_handler.load_data(data_handler, vuln_v2)

    with self.server(data_handler):
      imp.run()

    # 5. Check that modified affected now in datastore.
    mock_publish.assert_called_once()
    bug_v2 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v2)
    self.assertEqual('Summary v1', bug_v2.summary)
    self.assertEqual(1, len(bug_v2.affected_packages))
    self.assertEqual('package-b', bug_v2.affected_packages[0].package.name)
    self.assertNotEqual(v1_checksum, bug_v2.affected_checksum)
    v2_checksum = bug_v2.affected_checksum

    mock_publish.reset_mock()

    # 6. Manually modify the Bug.affected (to pretend it's been enriched).
    enriched_package = osv.AffectedPackage(
        package=osv.Package(name='package-b', ecosystem='PyPI'),
        ecosystem_specific={'extra_data': 'enriched'})
    bug_v2.affected_packages = [enriched_package]
    bug_v2.put()

    # 7. Rerun import for record w/ modified summary (but affected the same).
    vuln_v3 = f'''[{{
       "id": "{test_id}",
       "modified": "2023-01-03T00:00:00Z",
       "schema_version": "1.3.0",
       "summary": "Summary v3",
       "affected": [
         {{
           "package": {{ "name": "package-b", "ecosystem": "PyPI" }},
           "versions": [ "2.0.0" ]
         }}
       ]
    }}]'''
    data_handler.last_modified = 'Mon, 03 Jan 2023 00:00:00 GMT'
    data_handler.load_data(data_handler, vuln_v3)

    with self.server(data_handler):
      imp.run()

    # 8. Check that summary has been updated, but not affected.
    mock_publish.assert_called_once()
    bug_v3 = osv.Bug.get_by_id(test_id)
    self.assertIsNotNone(bug_v3)
    self.assertEqual('Summary v3', bug_v3.summary)
    self.assertEqual(1, len(bug_v3.affected_packages))
    self.assertEqual('package-b', bug_v3.affected_packages[0].package.name)
    # This is the key check: the enriched data should still be there.
    self.assertEqual({'extra_data': 'enriched'},
                     bug_v3.affected_packages[0].ecosystem_specific)
    # The checksum should be the same as before enrichment, as it's based on
    # the raw vuln.
    self.assertEqual(v2_checksum, bug_v3.affected_checksum)


@mock.patch('importer.utcnow',
            lambda: datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC))
class ImportFindingsTest(unittest.TestCase):
  """Import Finding tests."""

  @classmethod
  def setUpClass(cls):
    # Start the emulator BEFORE creating the ndb client
    cls.emulator = cls.enterClassContext(tests.datastore_emulator())
    cls.enterClassContext(ndb.Client().context(cache_policy=False))

  def setUp(self):
    self.emulator.reset()
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)
    warnings.filterwarnings('ignore', category=SystemTimeWarning)

  def test_add_finding(self):
    """Test that creating an import finding works."""
    expected = osv.ImportFinding(
        bug_id='CVE-2024-1234',
        source='cve-osv',
        findings=[
            osv.ImportFindings.INVALID_VERSION,
        ],
        first_seen=importer.utcnow(),
        last_attempt=importer.utcnow(),
    ).to_dict()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False, False)
    # pylint: disable-next=protected-access
    imp._record_quality_finding('cve-osv', 'CVE-2024-1234',
                                osv.ImportFindings.INVALID_VERSION)

    actual = osv.ImportFinding.get_by_id(expected['bug_id']).to_dict()
    self.assertEqual(expected, actual)


def setUpModule():
  """Set up the test module."""
  logging.getLogger().setLevel(logging.ERROR)
  logging.getLogger("UpstreamTest.test_compute_upstream").setLevel(
      logging.DEBUG)


if __name__ == '__main__':
  unittest.main()
