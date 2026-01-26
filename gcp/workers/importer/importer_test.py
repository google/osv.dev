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
import json
import logging
import threading

from unittest import mock
from urllib3.exceptions import SystemTimeWarning
import warnings

from google.cloud import ndb
from google.cloud import storage
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

  @mock.patch('google.cloud.storage.Blob.upload_from_string')
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_bucket(self, unused_mock_time: mock.MagicMock,
                  mock_publish: mock.MagicMock,
                  upload_from_str: mock.MagicMock):
    """Test bucket updates."""
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)

    with self.assertLogs(level='WARNING') as logs:
      imp.run()

    self.assertEqual(
        5,
        len(logs.output),
        msg=(f'Expected number of WARNING level (or higher) '
             f'logs not found {logs.output}'))
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0],
        msg='Expected schema validation failure log not found')
    self.assertIn(
        'WARNING:root:Invalid data:',
        logs.output[1],
        msg='Expected schema validation failure log not found')
    self.assertIn(
        "ERROR:root:Failed to parse vulnerability a/b/test-invalid.json: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2],
        msg='Expected schema validation failure log not found')

    # Check parse failure finding was recorded correctly.
    self.assertIn(
        osv.ImportFinding(
            bug_id='GO-2021-0085',
            source='test',
            findings=[osv.ImportFindings.INVALID_JSON],
            first_seen=importer.utcnow(),
            last_attempt=importer.utcnow()).to_dict(),
        [r.to_dict() for r in osv.ImportFinding.query()])
    self.assertEqual(
        1,
        len(list(osv.ImportFinding.query())),
        msg="Expected number of adverse import findings not found")

    # Check if vulnerability parse failure was logged correctly.
    self.assertTrue(
        any(('Failed to parse vulnerability (when considering for import)'
             ' "a/b/test-invalid.json"') in x[0][0]
            for x in upload_from_str.call_args_list),
        msg=('Expected schema validation failure not logged in public log '
             'bucket'))

    # Expected pubsub calls for validly imported records.
    mock_publish.assert_has_calls([
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='test',
            path='a/b/android-test.json',
            original_sha256=('12453f85cd87bc1d465e0d013db572c0'
                             '1f7fb7de3b3a33de94ebcc7bd0f23a14'),
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1645053056'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='test',
            path='a/b/test.json',
            original_sha256=('62966a80f6f9f54161803211069216177'
                             '37340a47f43356ee4a1cabe8f089869'),
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1683180616'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='test',
            path='a/b/CVE-2022-0128.json',
            original_sha256=('a4060cb842363cb6ae7669057402ccddc'
                             'e21a94ed6cad98234e73305816a86d3'),
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1671420222'),
    ],
                                  any_order=True)

    # Test this entry is not published, as it is preexisting and not newer.
    dsa_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='test',
        path='a/b/DSA-3029-1.json',
        original_sha256=mock.ANY,
        deleted='false')
    self.assertNotIn(
        dsa_call,
        mock_publish.mock_calls,
        msg='Old record was processed unexpectedly')

    # Test invalid entry is not published, as it failed validation.
    invalid_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='test',
        path='a/b/test-invalid.json',
        original_sha256=mock.ANY,
        deleted=mock.ANY)
    self.assertNotIn(
        invalid_call,
        mock_publish.mock_calls,
        msg='Invalid record was processed unexpectedly')

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_bucket_deletion(self, unused_mock_time: mock.MagicMock,
                           mock_publish: mock.MagicMock):
    """Test bucket deletion."""
    imp = importer.Importer(
        'fake_public_key',
        'fake_private_key',
        self.tmp_dir,
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET,
        'bucket',
        True,
        True,
        # The test dataset is too small for the safety threshold.
        deletion_safety_threshold_pct=100)

    with self.assertLogs(level='WARNING') as logs:
      imp.run()
    self.assertEqual(
        3,
        len(logs.output),
        msg='Expected number of WARNING level (or higher) logs not found')
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0])
    self.assertIn('WARNING:root:Invalid data:', logs.output[1])
    self.assertIn(
        "ERROR:root:Failed to parse vulnerability a/b/test-invalid.json: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2])

    # Test existing record in Datastore no longer present in GCS has been
    # requested to be deleted.
    deletion_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='test',
        path='a/b/CVE-2018-1000030.json',
        original_sha256='',
        deleted='true',
        req_timestamp='12345',
        src_timestamp='')
    mock_publish.assert_has_calls([deletion_call])

    # Test existing record in Datastore with an ID containing a colon and no
    # longer present in GCS has been requested to be deleted and is correctly
    # formed.
    deletion_call = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='test',
        path='RXSA-2023:0101.json',
        original_sha256='',
        deleted='true',
        req_timestamp='12345',
        src_timestamp='')
    mock_publish.assert_has_calls([deletion_call])

    # Run again with a 10% threshold and confirm the safeguards work as
    # intended.
    imp = importer.Importer(
        'fake_public_key',
        'fake_private_key',
        self.tmp_dir,
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET,
        'bucket',
        True,
        True,
        # The test dataset is so small this safety threshold triggers.
        deletion_safety_threshold_pct=10)

    mock_publish.reset_mock()

    with self.assertLogs(level='WARNING') as logs:
      imp.run()
    # The schema validation of failures of the files in GCS by
    # _process_deletions_bucket() causes, plus an extra one from the safeguard.
    self.assertEqual(4, len(logs.output))
    self.assertEqual(
        "ERROR:root:Cowardly refusing to delete 2 missing records from GCS for: test",  # pylint: disable=line-too-long
        logs.output[-1])

    # No deletions should have been requested.
    self.assertNotIn(deletion_call, mock_publish.mock_calls)

  @mock.patch('google.cloud.storage.Blob.upload_from_string')
  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_import_override(self, unused_mock_time: mock.MagicMock,
                           mock_publish: mock.MagicMock,
                           upload_from_str: mock.MagicMock):
    """Test behavior of ignore_last_import_time source setting."""

    self.source_repo.ignore_last_import_time = True
    self.source_repo.put()

    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)

    expected_pubsub_message = mock.call(
        self.tasks_topic,
        data=b'',
        type='update',
        source='test',
        path='a/b/DSA-3029-1.json',
        original_sha256=mock.ANY,
        deleted='false',
        req_timestamp='12345',
        src_timestamp='')

    with self.assertLogs(level='WARNING') as logs:
      imp.run()

    # Confirm invalid records were treated as expected.
    self.assertEqual(
        5,
        len(logs.output),
        msg=('Expected number of WARNING level (or higher) logs '
             '(from first run) not found'))
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0])
    self.assertIn('WARNING:root:Invalid data:', logs.output[1])
    self.assertIn(
        "ERROR:root:Failed to parse vulnerability a/b/test-invalid.json: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2])

    # Check parse failure finding was recorded correctly.
    self.assertEqual(
        1,
        len(list(osv.ImportFinding.query())),
        msg="Expected number of adverse import findings not found")

    # Check if vulnerability parse failure was logged correctly.
    self.assertTrue(
        any(('Failed to parse vulnerability (when considering for import) '
             '"a/b/test-invalid.json"') in x[0][0]
            for x in upload_from_str.call_args_list))

    # Confirm a pubsub message was emitted for record reimported.
    mock_publish.assert_has_calls([
        expected_pubsub_message,
    ])
    mock_publish.reset_mock()

    # Second run should not reimport existing records again, since each import
    # run resets the value of source_repo.ignore_last_import_time to False
    with self.assertLogs(level='WARNING') as logs:
      imp.run()

    # Confirm invalid records were (again) treated as expected.
    self.assertEqual(
        5,
        len(logs.output),
        msg=('Expected number of WARNING level (or higher) logs '
             '(from second run) not found'))
    self.assertEqual(
        "WARNING:root:Failed to validate loaded OSV entry: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[0])
    self.assertIn('WARNING:root:Invalid data:', logs.output[1])
    self.assertIn(
        "ERROR:root:Failed to parse vulnerability a/b/test-invalid.json: 'modified' is a required property",  # pylint: disable=line-too-long
        logs.output[2])

    # Check if vulnerability parse failure was logged correctly.
    self.assertTrue(
        any(('Failed to parse vulnerability (when considering for import) '
             '"a/b/test-invalid.json"') in x[0][0]
            for x in upload_from_str.call_args_list))

    # Confirm second run didn't reprocess any existing records.
    self.assertNotIn(expected_pubsub_message, mock_publish.mock_calls)

  def test_blob_parsing(self):
    """Test conditional GCS blob parsing works correctly."""

    imp = importer.Importer(
        'fake_public_key',
        'fake_private_key',
        self.tmp_dir,
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET,
        'bucket',
        True,
        False,
        deletion_safety_threshold_pct=100)

    if not self.source_repo.last_update_date:
      self.source_repo.last_update_date = datetime.datetime.min.replace(
          tzinfo=datetime.UTC)

    storage_client = storage.Client()
    # Reuse the NDB client already created in __main__
    datastore_client = self.ndb_context.client
    blob = storage.Blob(
        'a/b/CVE-2022-0128.json',
        storage.Bucket(storage_client, TEST_BUCKET),
        generation=None)
    vs = osv.parse_vulnerabilities_from_data(blob.download_as_bytes(), '.json')

    # pylint: disable-next=protected-access
    result = imp._convert_blob_to_vuln(storage_client, datastore_client,
                                       self.source_repo, blob, False)
    self.assertEqual(
        result,
        ('a4060cb842363cb6ae7669057402ccddce21a94ed6cad98234e73305816a86d3',
         'a/b/CVE-2022-0128.json', None, vs))

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
  def test_all_updated(self, unused_mock_time: mock.MagicMock,
                       mock_publish: mock.MagicMock):
    """Testing basic rest endpoint import"""
    data_handler = MockDataHandler
    data_handler.last_modified = 'Mon, 01 Jan 2024 00:00:00 GMT'
    data_handler.load_file(data_handler, 'rest_test.json')
    self.source_repo.last_update_date = datetime.datetime(
        2020, 1, 1, tzinfo=datetime.UTC)
    repo = self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False, False)
    with self.server(data_handler):
      imp.run()
    self.assertEqual(mock_publish.call_count, data_handler.cve_count)
    self.assertEqual(
        repo.get().last_update_date,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC),
        msg='Expected last_update_date to equal REST Last-Modified date')

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_last_update_ignored(self, unused_mock_time: mock.MagicMock,
                               mock_publish: mock.MagicMock):
    """Testing last update ignored"""
    data_handler = MockDataHandler
    data_handler.last_modified = 'Mon, 01 Jan 2024 00:00:00 GMT'
    data_handler.load_file(data_handler, 'rest_test.json')
    self.source_repo.last_update_date = datetime.datetime(
        2023, 6, 6, tzinfo=datetime.UTC)
    self.source_repo.ignore_last_import_time = True
    repo = self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False, False)
    with self.server(data_handler):
      imp.run()
    self.assertEqual(mock_publish.call_count, data_handler.cve_count)
    self.assertEqual(
        repo.get().last_update_date,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC),
        msg='Expected last_update_date to equal REST Last-Modified date')

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_no_updates(self, unused_mock_time: mock.MagicMock,
                      mock_publish: mock.MagicMock):
    """Testing none last modified"""
    MockDataHandler.last_modified = 'Fri, 01 Jan 2021 00:00:00 GMT'
    self.source_repo.last_update_date = datetime.datetime(
        2024, 2, 1, tzinfo=datetime.UTC)
    repo = self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            True, False)
    with self.assertLogs() as logs, self.server(MockDataHandler):
      imp.run()
    mock_publish.assert_not_called()
    self.assertIn('INFO:root:No changes since last update.', logs.output[1])
    self.assertEqual(
        repo.get().last_update_date,
        datetime.datetime(2024, 2, 1, tzinfo=datetime.UTC),
        msg='last_update_date should not have been updated')

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_few_updates(self, unused_mock_time: mock.MagicMock,
                       mock_publish: mock.MagicMock):
    """Testing from date between entries - 
    only entries after 6/6/2023 should be called"""
    MockDataHandler.last_modified = 'Mon, 01 Jan 2024 00:00:00 GMT'
    self.source_repo.last_update_date = datetime.datetime(
        2023, 6, 6, tzinfo=datetime.UTC)
    repo = self.source_repo.put()
    imp = importer.Importer('fake_public_key', 'fake_private_key', self.tmp_dir,
                            importer.DEFAULT_PUBLIC_LOGGING_BUCKET, 'bucket',
                            False, False)
    with self.server(MockDataHandler):
      imp.run()
    mock_publish.assert_has_calls([
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='curl',
            path='CURL-CVE-2023-46219.json',
            original_sha256='dd4766773f12e14912d7c930669a2650'
            '2a83c80151815cb49400462067ab704e',
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1701684728'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='curl',
            path='CURL-CVE-2023-46218.json',
            original_sha256='ed5d9ee8fad738687254138fdbfd6da0'
            'f6a3eccbc9ffcda12fb484d63448a22f',
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1701684985'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='curl',
            path='CURL-CVE-2023-38546.json',
            original_sha256='61425ff4651524a71daa90c66235a2af'
            'b09a06faa839fe4af010a5a02f3dafb7',
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1697013410'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='curl',
            path='CURL-CVE-2023-38545.json',
            original_sha256='f76bcb2dedf63b51b3195f2f27942dc2'
            '3c87f2bc3a93dec79ea838b4c1ffb412',
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1700412273'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='curl',
            path='CURL-CVE-2023-38039.json',
            original_sha256='fcac007c2f0d2685fa56c5910a0e24bc'
            '0587efc409878fcb0df5b096db5d205f',
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1694717842'),
        mock.call(
            self.tasks_topic,
            data=b'',
            type='update',
            source='curl',
            path='CURL-CVE-2023-28321.json',
            original_sha256='f8bf8e7e18662ca0c1ddd4a3f90ac4a9'
            '6fc730f09e3bff00c63d99d61b0697b2',
            deleted='false',
            req_timestamp='12345',
            src_timestamp='1696205251')
    ])
    self.assertEqual(
        repo.get().last_update_date,
        datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC),
        msg='Expected last_update_date to equal REST Last-Modified date')

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

  @mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
  @mock.patch('time.time', return_value=12345.0)
  def test_rest_deletion(self, unused_mock_time: mock.MagicMock,
                         mock_publish: mock.MagicMock):
    """Test REST deletion."""
    # Setup existing bugs in Datastore
    # Bug 1: Exists in REST (should NOT be deleted)
    osv.Bug(
        id='OSV-DEL-REST-1',
        db_id='OSV-DEL-REST-1',
        status=1,
        source='curl',
        source_id='curl:OSV-DEL-REST-1.json',
        public=True,
        affected_packages=[{
            'package': {
                'ecosystem': 'PyPI',
                'name': 'pkg1'
            }
        }]).put()

    # Bug 2: Missing from REST (SHOULD be deleted)
    osv.Bug(
        id='OSV-DEL-REST-2',
        db_id='OSV-DEL-REST-2',
        status=1,
        source='curl',
        source_id='curl:OSV-DEL-REST-2.json',
        public=True,
        affected_packages=[{
            'package': {
                'ecosystem': 'PyPI',
                'name': 'pkg2'
            }
        }]).put()

    # Bug 3: Withdrawn (should be ignored)
    osv.Bug(
        id='OSV-DEL-REST-3',
        db_id='OSV-DEL-REST-3',
        status=1,
        source='curl',
        source_id='curl:OSV-DEL-REST-3.json',
        public=True,
        withdrawn=datetime.datetime(2024, 1, 1, tzinfo=datetime.UTC),
        affected_packages=[{
            'package': {
                'ecosystem': 'PyPI',
                'name': 'pkg3'
            }
        }]).put()

    # Mock REST API response
    data_handler = MockDataHandler
    data_handler.last_modified = 'Mon, 01 Jan 2024 00:00:00 GMT'
    # OSV-DEL-REST-1 is old (2023), OSV-DEL-REST-NEW is new (2024).
    # We will set last_update_date to mid-2023 so OSV-DEL-REST-1 is skipped
    # but OSV-DEL-REST-NEW is processed.
    mock_data = [{
        'id': 'OSV-DEL-REST-1',
        'modified': '2023-01-01T00:00:00Z'
    }, {
        'id': 'OSV-DEL-REST-NEW',
        'modified': '2024-01-01T00:00:00Z',
        'schema_version': '1.3.0',
        'affected': [{
            'package': {
                'ecosystem': 'PyPI',
                'name': 'pkg-new'
            }
        }]
    }]
    data_handler.load_data(data_handler, json.dumps(mock_data))

    # Set last_update_date to skip REST-1
    self.source_repo.last_update_date = datetime.datetime(
        2023, 6, 1, tzinfo=datetime.UTC)
    self.source_repo.put()

    # Run 1: Update mode (delete=False)
    # This should update OSV-DEL-REST-NEW
    imp_update = importer.Importer(
        'fake_public_key',
        'fake_private_key',
        self.tmp_dir,
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET,
        'bucket',
        True,  # strict_validation
        False,  # delete=False
        deletion_safety_threshold_pct=100)

    # Run 2: Delete mode (delete=True)
    # This should delete OSV-DEL-REST-2
    imp_delete = importer.Importer(
        'fake_public_key',
        'fake_private_key',
        self.tmp_dir,
        importer.DEFAULT_PUBLIC_LOGGING_BUCKET,
        'bucket',
        True,  # strict_validation
        True,  # delete=True
        deletion_safety_threshold_pct=100)

    with self.assertLogs(level='INFO') as logs, self.server(data_handler):
      # Run 1: Update mode (delete=False)
      # This should update OSV-DEL-REST-NEW
      imp_update.run()

      # Run 2: Delete mode (delete=True)
      # This should delete OSV-DEL-REST-2
      imp_delete.run()

    # Verify calls:
    # 1. Update OSV-DEL-REST-NEW
    # 2. Delete OSV-DEL-REST-2
    if mock_publish.call_count != 2:
      self.fail(f'Expected 2 calls, got {mock_publish.call_count}. '
                f'Logs: {logs.output}')

    # Verify OSV-DEL-REST-2 deletion
    rest_2_calls = [
        c for c in mock_publish.call_args_list
        if c.kwargs.get('path') == 'OSV-DEL-REST-2.json'
    ]
    self.assertEqual(1, len(rest_2_calls))
    self.assertEqual('true', rest_2_calls[0].kwargs.get('deleted'))

    # Verify OSV-DEL-REST-NEW update
    rest_new_calls = [
        c for c in mock_publish.call_args_list
        if c.kwargs.get('path') == 'OSV-DEL-REST-NEW.json'
    ]
    self.assertEqual(1, len(rest_new_calls))
    self.assertEqual('false', rest_new_calls[0].kwargs.get('deleted', 'false'))


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

  unittest.enterModuleContext(tests.setup_gitter())


if __name__ == '__main__':
  unittest.main()
