# Copyright 2026 Google LLC
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
"""Tests for vanir_signatures."""

import unittest
from unittest import mock

from google.cloud import ndb

import osv
import osv.tests
import vanir_signatures
from osv import vulnerability_pb2


class VanirSignaturesTest(unittest.TestCase):
  """Tests for vanir_signatures."""

  @classmethod
  def setUpClass(cls):
    cls.emulator = cls.enterClassContext(osv.tests.datastore_emulator())
    cls.enterClassContext(ndb.Client().context(cache_policy=False))

  def setUp(self):
    self.emulator.reset()

  @mock.patch('osv.gcs.get_by_id_with_generation')
  def test_process_vulnerability_skip_existing_signatures(self, mock_get_gcs):
    """Test skipping when signatures already exist."""
    vuln_id = 'OSV-2026-123'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    affected = vuln.affected.add()
    affected.database_specific['vanir_signatures'] = []
    affected.ranges.add(
        type=vulnerability_pb2.Range.GIT, repo='https://example.com/repo')

    mock_get_gcs.return_value = (vuln, '123')

    with self.assertLogs(level='DEBUG') as cm:
      result = vanir_signatures.process_vulnerability(vuln_id)
      self.assertFalse(result)
      self.assertTrue(
          any('already has Vanir signatures' in log for log in cm.output))

  @mock.patch('osv.gcs.get_by_id_with_generation')
  def test_process_vulnerability_skip_no_git_ranges(self, mock_get_gcs):
    """Test skipping when no GIT ranges are present."""
    vuln_id = 'OSV-2026-123'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    vuln.affected.add()

    mock_get_gcs.return_value = (vuln, '123')

    with self.assertLogs(level='DEBUG') as cm:
      result = vanir_signatures.process_vulnerability(vuln_id)
      self.assertFalse(result)
      self.assertTrue(
          any('has no GIT affected ranges' in log for log in cm.output))

  @mock.patch('osv.gcs.get_by_id_with_generation')
  def test_process_vulnerability_skip_kernel(self, mock_get_gcs):
    """Test skipping kernel vulnerabilities."""
    vuln_id = 'CVE-2023-1234'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    affected = vuln.affected.add()
    affected.package.name = 'Kernel'
    affected.package.ecosystem = 'Linux'
    affected.ranges.add(
        type=vulnerability_pb2.Range.GIT,
        repo='https://example.com/kernel-repo')

    mock_get_gcs.return_value = (vuln, '123')

    with self.assertLogs(level='DEBUG') as cm:
      result = vanir_signatures.process_vulnerability(vuln_id)
      self.assertFalse(result)
      self.assertTrue(
          any('is a Kernel vulnerability' in log for log in cm.output))

  @mock.patch('osv.gcs.get_by_id_with_generation')
  @mock.patch('osv.gcs.upload_vulnerability')
  @mock.patch('vanir_signatures._generate_vanir_signatures')
  def test_process_vulnerability_success(self, mock_gen_signatures, mock_upload,
                                         mock_get_gcs):
    """Test successful signature generation."""
    vuln_id = 'OSV-2026-123'

    # Input vulnerability
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    affected = vuln.affected.add()
    affected.ranges.add(
        type=vulnerability_pb2.Range.GIT, repo='https://example.com/repo')

    mock_get_gcs.return_value = (vuln, '123')

    # Mock generation result
    enriched_vuln = vulnerability_pb2.Vulnerability()
    enriched_vuln.CopyFrom(vuln)
    enriched_vuln.affected[0].database_specific['vanir_signatures'] = [{
        'id': 'sig1'
    }]
    mock_gen_signatures.return_value = enriched_vuln

    # Setup Datastore Bug
    bug = osv.Bug(id=vuln_id, db_id=vuln_id, source='test')
    bug.put()

    result = vanir_signatures.process_vulnerability(vuln_id)

    self.assertTrue(result)
    mock_upload.assert_called_once()

    # Verify Datastore update
    updated_bug = osv.Bug.get_by_id(vuln_id)
    self.assertIn('vanir_signatures',
                  updated_bug.affected_packages[0].database_specific)


if __name__ == '__main__':
  unittest.main()
