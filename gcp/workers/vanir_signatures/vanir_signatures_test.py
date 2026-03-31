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

import datetime
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
  def test_process_batch_skip_no_git_ranges(self, mock_get_gcs):
    """Test skipping when no GIT ranges are present."""
    vuln_id = 'VULN-1'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    vuln.affected.add()

    mock_get_gcs.return_value = (vuln, '123')

    with self.assertLogs(level='DEBUG') as cm:
      result, failed_ids = vanir_signatures.process_batch([vuln_id])
      self.assertEqual(result, 0)
      self.assertEqual(failed_ids, [])
      self.assertTrue(any('no GIT affected ranges' in log for log in cm.output))

  @mock.patch('osv.gcs.get_by_id_with_generation')
  def test_process_batch_skip_kernel(self, mock_get_gcs):
    """Test skipping kernel vulnerabilities."""
    vuln_id = 'VULN-1'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    affected = vuln.affected.add()
    affected.package.name = 'Kernel'
    affected.package.ecosystem = 'Linux'
    affected.ranges.add(
        type=vulnerability_pb2.Range.GIT,
        repo='https://example.com/kernel-repo')

    mock_get_gcs.return_value = (vuln, '123')

    with self.assertLogs(level='DEBUG') as cm:
      result, failed_ids = vanir_signatures.process_batch([vuln_id])
      self.assertEqual(result, 0)
      self.assertEqual(failed_ids, [])
      self.assertTrue(
          any('is a Kernel vulnerability' in log for log in cm.output))

  @mock.patch('osv.gcs.get_by_id_with_generation')
  def test_process_batch_skip_withdrawn(self, mock_get_gcs):
    """Test skipping withdrawn vulnerabilities."""
    vuln_id = 'VULN-1'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    vuln.withdrawn.FromSeconds(1234567890)
    affected = vuln.affected.add()
    affected.ranges.add(
        type=vulnerability_pb2.Range.GIT, repo='https://example.com/repo')

    mock_get_gcs.return_value = (vuln, '123')

    with self.assertLogs(level='DEBUG') as cm:
      result, failed_ids = vanir_signatures.process_batch([vuln_id])
      self.assertEqual(result, 0)
      self.assertEqual(failed_ids, [])
      self.assertTrue(any('it is withdrawn' in log for log in cm.output))

  @mock.patch('osv.gcs.get_by_id_with_generation')
  @mock.patch('osv.gcs.upload_vulnerability')
  @mock.patch('vanir_signatures._generate_vanir_signatures_batch')
  def test_process_batch_success(self, mock_gen_signatures, mock_upload,
                                 mock_get_gcs):
    """Test successful signature generation."""
    vuln_id = 'VULN-1'

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
    mock_gen_signatures.return_value = {vuln_id: [enriched_vuln]}

    # Setup Datastore Vulnerability
    vuln_entity = osv.Vulnerability(id=vuln_id)
    vuln_entity.put()

    result, failed_ids = vanir_signatures.process_batch([vuln_id])

    self.assertEqual(result, 1)
    self.assertEqual(failed_ids, [])
    mock_upload.assert_called_once()
    mock_gen_signatures.assert_called_once_with([vuln])

    # Verify Datastore update
    updated_vuln = osv.Vulnerability.get_by_id(vuln_id)
    self.assertIsNotNone(updated_vuln.modified)

  @mock.patch('osv.gcs.get_by_id_with_generation')
  @mock.patch('osv.gcs.upload_vulnerability')
  @mock.patch('vanir_signatures._generate_vanir_signatures_batch')
  def test_process_batch_failure(self, mock_gen_signatures, mock_upload,
                                 mock_get_gcs):
    """Test GCS failure adding ID to retry list and skipping Datastore update"""
    vuln_id = 'VULN-1'
    vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
    affected = vuln.affected.add()
    affected.ranges.add(
        type=vulnerability_pb2.Range.GIT, repo='https://example.com/repo')

    mock_get_gcs.return_value = (vuln, '123')

    # Mock generation result (must be different from original to trigger update)
    enriched_vuln = vulnerability_pb2.Vulnerability()
    enriched_vuln.CopyFrom(vuln)
    enriched_vuln.affected[0].database_specific['vanir_signatures'] = [{
        'id': 'sig1'
    }]
    mock_gen_signatures.return_value = {vuln_id: [enriched_vuln]}
    mock_upload.side_effect = Exception('GCS down')

    # Setup Datastore Vulnerability
    vuln_entity = osv.Vulnerability(id=vuln_id)
    vuln_entity.modified = datetime.datetime(
        2026, 1, 1, tzinfo=datetime.timezone.utc)
    vuln_entity.put()
    initial_modified = vuln_entity.modified

    result, failed_ids = vanir_signatures.process_batch([vuln_id])

    # Result should be 0 because upload failed
    self.assertEqual(result, 0)
    self.assertEqual(failed_ids, [vuln_id])

    # Verify Datastore was NOT updated
    updated_vuln = osv.Vulnerability.get_by_id(vuln_id, use_cache=False)
    self.assertEqual(updated_vuln.modified, initial_modified)

  @mock.patch('osv.models.Vulnerability.query')
  @mock.patch('vanir_signatures.process_batch')
  def test_global_batching(self, mock_process_batch, mock_vuln_query):
    """Test performing global batching of all found vulnerabilities."""
    # Mock Vulnerability query with 150 items
    vuln_keys = [mock.Mock() for _ in range(150)]
    for i, k in enumerate(vuln_keys):
      k.id.return_value = f'VULN-{i}'

    mock_query = mock.Mock()
    mock_vuln_query.return_value = mock_query
    mock_query.filter.return_value = mock_query
    mock_query.iter.return_value = vuln_keys

    mock_process_batch.return_value = (10, [])

    # Run main with dry-run and batch_size=100
    with mock.patch(
        'argparse.ArgumentParser.parse_args',
        return_value=mock.Mock(
            dry_run=True, batch_size=100, max_workers=10, hours=None)):
      vanir_signatures.main()

    # Verify process_batch was called for each chunk (BATCH_SIZE=100)
    # 150 items -> 2 batches
    self.assertEqual(mock_process_batch.call_count, 2)

    # First batch of 100
    expected_batch1 = [f'VULN-{i}' for i in range(100)]
    mock_process_batch.assert_any_call(expected_batch1, True, 10)

    # Second batch of 50
    expected_batch2 = [f'VULN-{i}' for i in range(100, 150)]
    mock_process_batch.assert_any_call(expected_batch2, True, 10)


if __name__ == '__main__':
  unittest.main()
