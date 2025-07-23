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
import logging
import os

from google.cloud import storage


VULN_JSON_PATH = 'all/json/'
VULN_PB_PATH = 'all/pb/'

_storage_client = None

def _get_storage_client() -> storage.Client:
  global _storage_client
  if _storage_client is None:
    _storage_client = storage.Client()
  return _storage_client

def get_osv_bucket() -> storage.Bucket:
  """Gets the osv vulnerability bucket, from OSV_VULNERABILITIES_BUCKET"""
  try:
    bucket = os.environ['OSV_VULNERABILITIES_BUCKET']
    bucket = bucket.lstrip('gs://')
  except KeyError:
    logging.error('OSV_VULNERABILITIES_BUCKET environment variable not set')
    raise
  client = _get_storage_client()
  return client.bucket(bucket)
