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
"""Linter API tests."""

import unittest
from unittest import mock
from flask import Flask
import linter_api

class LinterApiTest(unittest.TestCase):

  def setUp(self):
    self.app = Flask(__name__)
    self.app.register_blueprint(linter_api.blueprint)
    self.client = self.app.test_client()

  @mock.patch('linter_api._get_storage_client')
  def test_list_sources(self, mock_get_client):
    mock_client = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_bucket = mock.Mock()
    mock_client.bucket.return_value = mock_bucket
    
    # Mock list_blobs to return prefixes
    mock_blobs = mock.Mock()
    mock_blobs.prefixes = {'linter-result/source1/', 'linter-result/source2/'}
    mock_blobs.__iter__ = mock.Mock(return_value=iter([])) # Emulate empty iterator for blobs themselves
    mock_client.list_blobs.return_value = mock_blobs

    response = self.client.get('/linter-findings/')
    self.assertEqual(response.status_code, 200)
    self.assertCountEqual(response.json, ['source1', 'source2'])
    
    mock_client.list_blobs.assert_called_with(
        linter_api.LINTER_BUCKET, prefix=linter_api.LINTER_PREFIX, delimiter='/')

  @mock.patch('linter_api._get_storage_client')
  def test_get_findings(self, mock_get_client):
    mock_client = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_bucket = mock.Mock()
    mock_client.bucket.return_value = mock_bucket
    
    mock_blob = mock.Mock()
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = True
    mock_blob.download_as_text.return_value = '{"findings": []}'

    response = self.client.get('/linter-findings/source1')
    self.assertEqual(response.status_code, 200)
    self.assertEqual(response.json, {'findings': []})
    
    mock_bucket.blob.assert_called_with('linter-result/source1/result.json')

  @mock.patch('linter_api._get_storage_client')
  def test_get_findings_not_found(self, mock_get_client):
    mock_client = mock.Mock()
    mock_get_client.return_value = mock_client
    mock_bucket = mock.Mock()
    mock_client.bucket.return_value = mock_bucket
    
    mock_blob = mock.Mock()
    mock_bucket.blob.return_value = mock_blob
    mock_blob.exists.return_value = False

    response = self.client.get('/linter-findings/source1')
    self.assertEqual(response.status_code, 404)

if __name__ == '__main__':
  unittest.main()
