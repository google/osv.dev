# Copyright 2025 Google LLC
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
"""Models tests."""

import datetime
import json
import os
import unittest

from . import models

from . import bug
from . import gcs
from . import sources
from . import tests
from . import vulnerability_pb2

from google.cloud import ndb


class ModelsTest(unittest.TestCase):
  """Tests for ndb Model migrations."""

  def setUp(self):
    models.SourceRepository(
        id='test',
        name='test',
        db_prefix=['TEST-'],
    ).put()
    return super().setUp()

  def test_bug_post_put(self):
    """Test _post_put_hook for Bug to populate new datastore/gcs entities."""
    vuln_id = 'TEST-123'
    # Create a handmade populated Bug
    models.AliasGroup(
        bug_ids=sorted([vuln_id, 'CVE-123', 'OSV-123']),
        last_modified=datetime.datetime(2025, 3, 4, tzinfo=datetime.UTC)).put()
    models.UpstreamGroup(
        db_id=vuln_id,
        upstream_ids=['TEST-1', 'TEST-12'],
        last_modified=datetime.datetime(2025, 3, 5, tzinfo=datetime.UTC)).put()
    models.Bug(
        db_id=vuln_id,
        aliases=['CVE-123'],
        related=['TEST-234'],
        upstream_raw=['TEST-12'],
        summary='This is a vuln',
        severities=[
            models.Severity(type='CVSS_V2', score='AV:N/AC:L/Au:S/C:P/I:P/A:N')
        ],
        status=bug.BugStatus.PROCESSED,
        timestamp=datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        last_modified=datetime.datetime(2025, 3, 3, tzinfo=datetime.UTC),
        import_last_modified=datetime.datetime(2025, 2, 2, tzinfo=datetime.UTC),
        source_id=f'test:{vuln_id}.json',
        source_of_truth=models.SourceOfTruth.SOURCE_REPO,
        public=True,
        affected_packages=[
            models.AffectedPackage(
                package=models.Package(ecosystem='npm', name='testjs'),
                ranges=[
                    models.AffectedRange2(
                        type='SEMVER',
                        events=[
                            models.AffectedEvent(type='fixed', value='1.0.0'),
                            models.AffectedEvent(type='introduced', value='0'),
                        ]),
                    models.AffectedRange2(
                        type='SEMVER',
                        events=[
                            models.AffectedEvent(
                                type='last_affected', value='2.2.0'),
                            models.AffectedEvent(
                                type='introduced', value='2.0.0'),
                        ])
                ],
                versions=['0.1.0', '0.2.0', '0.3.0', '2.0.0', '2.1.0',
                          '2.2.0']),
            models.AffectedPackage(
                package=models.Package(
                    ecosystem='Ubuntu:24.04:LTS', name='test'),
                ranges=[
                    models.AffectedRange2(
                        type='ECOSYSTEM',
                        events=[
                            models.AffectedEvent(type='introduced', value='0'),
                            models.AffectedEvent(type='fixed', value='1.0.0-3'),
                        ])
                ],
                versions=['1.0.0-1', '1.0.0-2'],
                severities=[models.Severity(type='Ubuntu', score='Low')]),
            models.AffectedPackage(
                package=models.Package(ecosystem='Ubuntu:25.04', name='test'),
                ranges=[
                    models.AffectedRange2(
                        type='ECOSYSTEM',
                        events=[
                            models.AffectedEvent(type='introduced', value='0'),
                            models.AffectedEvent(type='fixed', value='1.0.0-3'),
                        ])
                ],
                versions=['1.0.0-1', '1.0.0-2'],
                severities=[models.Severity(type='Ubuntu', score='High')]),
            models.AffectedPackage(
                package=models.Package(ecosystem='', name=''),
                ranges=[
                    models.AffectedRange2(
                        type='GIT', repo_url='https://github.com/test/test')
                ],
                versions=['v1', 'v2']),
        ],
    ).put()
    put_bug = models.Bug.get_by_id(vuln_id)
    self.assertIsNotNone(put_bug)
    put_bug: models.Bug

    # Check if new db entities were created.
    vulnerability = models.Vulnerability.get_by_id(vuln_id)
    self.assertIsNotNone(vulnerability)
    vulnerability: models.Vulnerability
    self.assertEqual('test:TEST-123.json', vulnerability.source_id)
    self.assertEqual(
        datetime.datetime(2025, 3, 5, tzinfo=datetime.UTC),
        vulnerability.modified)
    self.assertFalse(vulnerability.is_withdrawn)
    self.assertEqual(
        datetime.datetime(2025, 2, 2, tzinfo=datetime.UTC),
        vulnerability.modified_raw)
    self.assertListEqual(['CVE-123'], vulnerability.alias_raw)
    self.assertListEqual(['TEST-234'], vulnerability.related_raw)
    self.assertListEqual(['TEST-12'], vulnerability.upstream_raw)

    listed_vuln = models.ListedVulnerability.get_by_id(vuln_id)
    self.assertIsNotNone(listed_vuln)
    listed_vuln: models.ListedVulnerability
    self.assertEqual(
        datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        listed_vuln.published)
    self.assertListEqual(['GIT', 'Ubuntu', 'npm'], listed_vuln.ecosystems)
    self.assertListEqual([
        'Ubuntu:24.04:LTS/test', 'Ubuntu:25.04/test', 'github.com/test/test',
        'npm/testjs'
    ], listed_vuln.packages)
    self.assertEqual('This is a vuln', listed_vuln.summary)
    self.assertTrue(listed_vuln.is_fixed)
    self.assertListEqual([
        models.Severity(type='CVSS_V2', score='AV:N/AC:L/Au:S/C:P/I:P/A:N'),
        models.Severity(type='Ubuntu', score='High'),
        models.Severity(type='Ubuntu', score='Low')
    ], listed_vuln.severities)
    self.assertListEqual(
        ['https://github.com/test/test', 'test', 'test-123', 'testjs'],
        listed_vuln.autocomplete_tags)
    # search_indices should include all the original search indices,
    # plus the transitive alias & upstream ids
    search_indices = sorted(put_bug.search_indices +
                            ['osv-123', 'osv', 'test-1', '1'])
    self.assertListEqual(search_indices, listed_vuln.search_indices)

    affected: list[models.AffectedVersions] = models.AffectedVersions.query(
        models.AffectedVersions.vuln_id == vuln_id).fetch()
    affected.sort(key=lambda x: x.sort_key())
    want = [
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='GIT',
            name='https://github.com/test/test',
            versions=['v1', 'v2']),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu',
            name='test',
            events=[
                models.AffectedEvent(type='introduced', value='0'),
                models.AffectedEvent(type='fixed', value='1.0.0-3')
            ]),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu',
            name='test',
            versions=['1.0.0-1', '1.0.0-2']),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu:24.04',
            name='test',
            events=[
                models.AffectedEvent(type='introduced', value='0'),
                models.AffectedEvent(type='fixed', value='1.0.0-3')
            ]),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu:24.04',
            name='test',
            versions=['1.0.0-1', '1.0.0-2']),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu:24.04:LTS',
            name='test',
            events=[
                models.AffectedEvent(type='introduced', value='0'),
                models.AffectedEvent(type='fixed', value='1.0.0-3')
            ]),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu:24.04:LTS',
            name='test',
            versions=['1.0.0-1', '1.0.0-2']),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu:25.04',
            name='test',
            events=[
                models.AffectedEvent(type='introduced', value='0'),
                models.AffectedEvent(type='fixed', value='1.0.0-3')
            ]),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='Ubuntu:25.04',
            name='test',
            versions=['1.0.0-1', '1.0.0-2']),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='npm',
            name='testjs',
            events=[
                models.AffectedEvent(type='introduced', value='0'),
                models.AffectedEvent(type='fixed', value='1.0.0')
            ]),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='npm',
            name='testjs',
            events=[
                models.AffectedEvent(type='introduced', value='2.0.0'),
                models.AffectedEvent(type='last_affected', value='2.2.0')
            ]),
        models.AffectedVersions(
            vuln_id=vuln_id,
            ecosystem='npm',
            name='testjs',
            versions=['0.1.0', '0.2.0', '0.3.0', '2.0.0', '2.1.0', '2.2.0']),
    ]
    self.assertListEqual([a.to_dict() for a in want],
                         [a.to_dict() for a in affected])

    # Check the records written to the 'bucket' (which is mocked) are expected.
    vuln_pb = put_bug.to_vulnerability(True, True, True)

    bucket = gcs.get_osv_bucket()
    blob = bucket.get_blob(os.path.join(gcs.VULN_PB_PATH, f'{vuln_id}.pb'))
    self.assertIsNotNone(blob)
    self.assertEqual(blob.custom_time,
                     datetime.datetime(2025, 3, 5, tzinfo=datetime.UTC))
    got_pb = vulnerability_pb2.Vulnerability().FromString(
        blob.download_as_bytes())
    self.assertEqual(got_pb, vuln_pb)

    blob = bucket.get_blob(os.path.join(gcs.VULN_JSON_PATH, f'{vuln_id}.json'))
    self.assertIsNotNone(blob)
    self.assertEqual(blob.custom_time,
                     datetime.datetime(2025, 3, 5, tzinfo=datetime.UTC))
    got_json = json.loads(blob.download_as_bytes())
    self.assertDictEqual(got_json, sources.vulnerability_to_dict(vuln_pb))

  def test_bug_withdraw(self):
    """Test if withdrawing a Bug correctly removes unneeded indices."""
    # First put the bug un-withdrawn
    vuln_id = 'TEST-999'
    models.Bug(
        db_id=vuln_id,
        status=bug.BugStatus.PROCESSED,
        timestamp=datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        last_modified=datetime.datetime(2025, 3, 3, tzinfo=datetime.UTC),
        import_last_modified=datetime.datetime(2025, 2, 2, tzinfo=datetime.UTC),
        source_id=f'test:{vuln_id}.json',
        source_of_truth=models.SourceOfTruth.SOURCE_REPO,
        public=True,
        affected_packages=[
            models.AffectedPackage(
                package=models.Package(ecosystem='PyPI', name='testpy'),
                ranges=[
                    models.AffectedRange2(
                        type='ECOSYSTEM',
                        events=[
                            models.AffectedEvent(type='introduced', value='0'),
                            models.AffectedEvent(type='fixed', value='1.0'),
                        ])
                ],
                versions=['0.1', '0.2'],
            ),
        ],
    ).put()
    put_bug = models.Bug.get_by_id(vuln_id)
    self.assertIsNotNone(put_bug)
    put_bug: models.Bug

    vulnerability = models.Vulnerability.get_by_id(vuln_id)
    self.assertIsNotNone(vulnerability)
    vulnerability: models.Vulnerability
    self.assertFalse(vulnerability.is_withdrawn)
    listed_vuln = models.ListedVulnerability.get_by_id(vuln_id)
    self.assertIsNotNone(listed_vuln)
    affected = models.AffectedVersions.query(
        models.AffectedVersions.vuln_id == vuln_id).fetch()
    self.assertEqual(2, len(affected))

    bucket = gcs.get_osv_bucket()
    blob = bucket.get_blob(os.path.join(gcs.VULN_PB_PATH, f'{vuln_id}.pb'))
    self.assertIsNotNone(blob)
    self.assertEqual(blob.custom_time,
                     datetime.datetime(2025, 3, 3, tzinfo=datetime.UTC))
    blob = bucket.get_blob(os.path.join(gcs.VULN_JSON_PATH, f'{vuln_id}.json'))
    self.assertIsNotNone(blob)
    self.assertEqual(blob.custom_time,
                     datetime.datetime(2025, 3, 3, tzinfo=datetime.UTC))

    # Now withdraw the Bug
    put_bug.withdrawn = datetime.datetime(2025, 4, 4, tzinfo=datetime.UTC)
    put_bug.last_modified = datetime.datetime(2025, 4, 4, tzinfo=datetime.UTC)
    put_bug.put()

    # Vulnerability exists, but is withdrawn
    vulnerability = models.Vulnerability.get_by_id(vuln_id)
    self.assertIsNotNone(vulnerability)
    vulnerability: models.Vulnerability
    self.assertTrue(vulnerability.is_withdrawn)
    # ListedVulnerability and AffectedVersions have been removed
    listed_vuln = models.ListedVulnerability.get_by_id(vuln_id)
    self.assertIsNone(listed_vuln)
    affected = models.AffectedVersions.query(
        models.AffectedVersions.vuln_id == vuln_id).fetch()
    self.assertEqual(0, len(affected))
    # Blobs still exist, and were re-written
    bucket = gcs.get_osv_bucket()
    blob = bucket.get_blob(os.path.join(gcs.VULN_PB_PATH, f'{vuln_id}.pb'))
    self.assertIsNotNone(blob)
    self.assertEqual(blob.custom_time,
                     datetime.datetime(2025, 4, 4, tzinfo=datetime.UTC))
    blob = bucket.get_blob(os.path.join(gcs.VULN_JSON_PATH, f'{vuln_id}.json'))
    self.assertIsNotNone(blob)
    self.assertEqual(blob.custom_time,
                     datetime.datetime(2025, 4, 4, tzinfo=datetime.UTC))

  def test_oss_fuzz_private(self):
    """Test that non-public Bugs from OSS-Fuzz are not indexed."""
    vuln_id = 'TEST-OSSFUZZ'
    models.Bug(
        db_id=vuln_id,
        status=bug.BugStatus.UNPROCESSED,
        public=False,
        timestamp=datetime.datetime(2025, 1, 1, tzinfo=datetime.UTC),
        last_modified=datetime.datetime(2025, 3, 3, tzinfo=datetime.UTC),
        import_last_modified=datetime.datetime(2025, 2, 2, tzinfo=datetime.UTC),
        source_id=f'test:{vuln_id}.json',
        source_of_truth=models.SourceOfTruth.SOURCE_REPO,
        affected_packages=[
            models.AffectedPackage(
                package=models.Package(ecosystem='PyPI', name='testpy'),
                ranges=[
                    models.AffectedRange2(
                        type='ECOSYSTEM',
                        events=[
                            models.AffectedEvent(type='introduced', value='0'),
                            models.AffectedEvent(type='fixed', value='1.0'),
                        ])
                ],
                versions=['0.1', '0.2'],
            ),
        ],
    ).put()

    vulnerability = models.Vulnerability.get_by_id(vuln_id)
    self.assertIsNone(vulnerability)
    listed_vuln = models.ListedVulnerability.get_by_id(vuln_id)
    self.assertIsNone(listed_vuln)
    affected = models.AffectedVersions.query(
        models.AffectedVersions.vuln_id == vuln_id).fetch()
    self.assertEqual(0, len(affected))
    bucket = gcs.get_osv_bucket()
    blob = bucket.get_blob(os.path.join(gcs.VULN_PB_PATH, f'{vuln_id}.pb'))
    self.assertIsNone(blob)
    blob = bucket.get_blob(os.path.join(gcs.VULN_JSON_PATH, f'{vuln_id}.json'))
    self.assertIsNone(blob)


def setUpModule():
  """Set up the test module."""
  tests.start_datastore_emulator()
  ndb_client = ndb.Client()
  unittest.enterModuleContext(ndb_client.context(cache_policy=False))


def tearDownModule():
  """Tear down the test module."""
  tests.stop_emulator()


if __name__ == '__main__':
  unittest.main()
