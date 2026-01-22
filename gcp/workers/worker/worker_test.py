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
import logging
import os
import shutil
import tempfile
import threading
import warnings
import unittest
from unittest import mock

from google.cloud import ndb
from google.protobuf.json_format import MessageToDict
import pygit2

import osv
from osv import tests
from osv import vulnerability_pb2
import oss_fuzz
import worker

TEST_BUCKET = 'test-osv-source-bucket'
TEST_DATA_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), 'testdata')

ndb_client = None
ds_emulator = None
context_manager = None

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


class RESTUpdateTest(unittest.TestCase, tests.ExpectationTest(TEST_DATA_DIR)):
  """Vulnerability update tests."""

  def setUp(self):
    self.maxDiff = None
    ds_emulator.reset()
    tests.mock_datetime(self)

    # Initialise fake source_repo.
    self.tmp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp_dir.cleanup)

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
    # self.tmp_dir.cleanup()

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
    vuln_pb = vulnerability_pb2.Vulnerability(id='CURL-CVE-2022-32221')
    vuln_pb.modified.FromDatetime(datetime.datetime(2020, 1, 1, 0, 0, tzinfo=datetime.UTC))
    vuln_ds = osv.Vulnerability(
        id='CURL-CVE-2022-32221',
        modified=datetime.datetime(2020, 1, 1, 0, 0, tzinfo=datetime.UTC),
        source_id='source:CURL-CVE-2022-32221.json',
        modified_raw=datetime.datetime(2020, 1, 1, 0, 0, tzinfo=datetime.UTC),
    )
    osv.put_entities(vuln_ds, vuln_pb)
    osv.gcs.upload_vulnerability(vuln_pb)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': solo_endpoint,
        'original_sha256': sha,
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('update_no_introduced', MessageToDict(osv.gcs.get_by_id('CURL-CVE-2022-32221')))


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

  def _put_vuln(self, vuln: vulnerability_pb2.Vulnerability, source_id: str):
    ds_vuln = osv.Vulnerability(
        id=vuln.id,
        source_id=source_id,
        modified=vuln.modified.ToDatetime(datetime.UTC),
        is_withdrawn=vuln.HasField('withdrawn'),
        modified_raw=vuln.modified.ToDatetime(datetime.UTC),
        alias_raw=list(vuln.aliases),
        related_raw=list(vuln.related),
        upstream_raw=list(vuln.upstream),
    )
    osv.put_entities(ds_vuln, vuln)
    osv.gcs.upload_vulnerability(vuln)

  def setUp(self):
    self.maxDiff = None
    ds_emulator.reset()

    self.original_clone = osv.clone
    tests.mock_clone(self, func=self.mock_clone)

    tests.mock_datetime(self)

    # Initialise fake source_repo.
    self.tmp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.tmp_dir.cleanup)

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
        editable=False,
        repo_username='',
    )
    self.source_repo.put()

    vuln = vulnerability_pb2.Vulnerability(id='OSV-123')
    vuln.modified.FromDatetime(datetime.datetime(2021, 1, 1, 0, 0, tzinfo=datetime.UTC))
    vuln.published.CopyFrom(vuln.modified)
    self._put_vuln(vuln, 'source:OSV-123.yaml')
    vuln = vulnerability_pb2.Vulnerability(id='OSV-124')
    vuln.modified.FromDatetime(datetime.datetime(2021, 1, 1, 0, 0, tzinfo=datetime.UTC))
    vuln.published.CopyFrom(vuln.modified)
    self._put_vuln(vuln, 'source:OSV-124.yaml')
    vuln = vulnerability_pb2.Vulnerability(id='OSV-125')
    vuln.modified.FromDatetime(datetime.datetime(2021, 1, 1, 0, 0, tzinfo=datetime.UTC))
    vuln.published.CopyFrom(vuln.modified)
    self._put_vuln(vuln, 'source:OSV-125.yaml')
    vuln = vulnerability_pb2.Vulnerability(id='OSV-127')
    vuln.modified.FromDatetime(datetime.datetime(2021, 1, 1, 0, 0, tzinfo=datetime.UTC))
    vuln.published.CopyFrom(vuln.modified)
    self._put_vuln(vuln, 'source:OSV-127.yaml')
    vuln = vulnerability_pb2.Vulnerability(id='OSV-131')
    vuln.modified.FromDatetime(datetime.datetime(2021, 1, 1, 0, 0, tzinfo=datetime.UTC))
    vuln.published.CopyFrom(vuln.modified)
    self._put_vuln(vuln, 'source:OSV-131.yaml')

    mock_publish = mock.patch('google.cloud.pubsub_v1.PublisherClient.publish')
    self.mock_publish = mock_publish.start()
    self.addCleanup(mock_publish.stop)

    osv.ecosystems.config.work_dir = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), 'testdata/tmp/')

    # Add fake ecosystems used in tests to supported ecosystems.
    osv.ecosystems._ecosystems._ecosystems.update({
        'ecosystem': None,
    })

  def tearDown(self):
    # self.tmp_dir.cleanup()
    pass

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

    self.expect_dict_equal('update', MessageToDict(osv.gcs.get_by_id('OSV-123')))

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

    self.expect_dict_equal('update_limit', MessageToDict(osv.gcs.get_by_id('OSV-128')))

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

    self.expect_dict_equal('update_no_introduced', MessageToDict(osv.gcs.get_by_id('OSV-127')))

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

    self.expect_dict_equal('update_new', MessageToDict(osv.gcs.get_by_id('OSV-126')))

  def test_update_delete(self):
    """Test deletion."""
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
    vuln = osv.Vulnerability.get_by_id('OSV-123')
    self.assertTrue(vuln.is_withdrawn)
    vuln_pb = osv.gcs.get_by_id('OSV-123')
    self.assertTrue(vuln_pb.HasField('withdrawn'))

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

    self.expect_dict_equal('update_pypi', MessageToDict(osv.gcs.get_by_id('PYSEC-123')))

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

    self.expect_dict_equal('normalized_pypi', MessageToDict(osv.gcs.get_by_id('PYSEC-456')))

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

    self.expect_dict_equal('update_last_affected', MessageToDict(osv.gcs.get_by_id('PYSEC-124')))

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

    self.expect_dict_equal('update_maven',
                           MessageToDict(osv.gcs.get_by_id('GHSA-838r-hvwh-24h8')))

    self.mock_publish.assert_not_called()

  def test_update_linux(self):
    """Test a Linux entry."""
    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('GSD-')
    self.source_repo.put()

    self.mock_repo.add_file(
        'GSD-123.yaml',
        self._load_test_data(os.path.join(TEST_DATA_DIR, 'GSD-123.yaml')),
    )
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'GSD-123.yaml',
        'original_sha256': _sha256('GSD-123.yaml'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('update_linux', MessageToDict(osv.gcs.get_by_id('GSD-123')))

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

    self.expect_dict_equal('update_bucket_0', MessageToDict(osv.gcs.get_by_id('GO-2021-0085')))

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

    self.expect_dict_equal('update_debian', MessageToDict(osv.gcs.get_by_id('DSA-3029-1')))

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

    self.expect_dict_equal('update_alpine', MessageToDict(osv.gcs.get_by_id('CVE-2022-27449')))

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
    self.expect_dict_equal('update_bucket_2', MessageToDict(osv.gcs.get_by_id('ASB-A-153358911')))

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

    self.expect_dict_equal('update_bad_ecosystem_new', MessageToDict(osv.gcs.get_by_id('OSV-129')))

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

    self.expect_dict_equal('update_partly_bad_ecosystem_new', MessageToDict(osv.gcs.get_by_id('OSV-130')))

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
    
    self.expect_dict_equal('update_partly_bad_ecosystem_delete', MessageToDict(osv.gcs.get_by_id('OSV-131')))

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
        'path': 'a/b/CVE-2016-15011.json',
        'original_sha256':
            ('88696731b137858e82177bdd9fe938eaa4e75507a2c9228fd21d98f91963ae90'
            ),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('update_bucket_cve', MessageToDict(osv.gcs.get_by_id('CVE-2016-15011')))

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

    self.expect_dict_equal('last_affected_git', MessageToDict(osv.gcs.get_by_id('OSV-TEST-last-affected-01')))

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

  def test_ubuntu_severity(self):
    """Test whether Ubuntu severity is parsed as expected."""

    self.source_repo.ignore_git = False
    self.source_repo.versions_from_repo = False
    self.source_repo.detect_cherrypicks = False
    self.source_repo.db_prefix.append('UBUNTU-CVE')
    self.source_repo.put()

    self.mock_repo.add_file(
        'UBUNTU-CVE-2025-38094.json',
        self._load_test_data(
            os.path.join(TEST_DATA_DIR, 'UBUNTU-CVE-2025-38094.json')),
    )
    self.mock_repo.commit('User', 'user@email')
    task_runner = worker.TaskRunner(ndb_client, None, self.tmp_dir.name, None,
                                    None)
    message = mock.Mock()
    message.attributes = {
        'source': 'source',
        'path': 'UBUNTU-CVE-2025-38094.json',
        'original_sha256': _sha256('UBUNTU-CVE-2025-38094.json'),
        'deleted': 'false',
    }
    task_runner._source_update(message)

    self.expect_dict_equal('ubuntu_severity_type', MessageToDict(osv.gcs.get_by_id('UBUNTU-CVE-2025-38094')))


def setUpModule():
  """Set up the test module."""
  print("Starting Datastore Emulator for the test suite...")
  # Silence logs coming from Vanir
  absl_logger = logging.getLogger('absl')
  absl_logger.setLevel(logging.CRITICAL)
  global ds_emulator, ndb_client
  # Start the emulator BEFORE creating the ndb client
  ds_emulator = unittest.enterModuleContext(tests.datastore_emulator())
  ndb_client = ndb.Client()
  unittest.enterModuleContext(ndb_client.context(cache_policy=False))
  unittest.enterModuleContext(tests.setup_gitter())


if __name__ == '__main__':
  unittest.main()
