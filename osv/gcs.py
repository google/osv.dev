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
"""Helpers for interacting with the OSV vulnerabilities in the GCS bucket."""
import datetime
import logging
import os

from google.cloud import storage
from google.protobuf import json_format

from .vulnerability_pb2 import Vulnerability

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


def get_by_id_with_generation(vuln_id: str) -> tuple[Vulnerability, int] | None:
  """Gets the OSV record, and the object's generation from the GCS bucket.
  Returns None if the record is not found.
  """
  bucket = get_osv_bucket()
  pb_blob = bucket.get_blob(os.path.join(VULN_PB_PATH, vuln_id + '.pb'))
  if pb_blob is None:
    return None
  try:
    vuln = Vulnerability.FromString(pb_blob.download_as_bytes())
    return vuln, pb_blob.generation
  except Exception:
    logging.exception('failed to download %s protobuf from GCS', vuln_id)
    raise


def upload_vulnerability(vulnerability: Vulnerability,
                         pb_generation: int | None = None):
  """Uploads the OSV record to the GCS bucket.
  If set, checks if the existing proto blob's generation matches pb_generation
  before uploading."""
  bucket = get_osv_bucket()
  vuln_id = vulnerability.id
  modified = vulnerability.modified.ToDatetime(datetime.UTC)
  try:
    pb_blob = bucket.blob(os.path.join(VULN_PB_PATH, vuln_id + '.pb'))
    pb_blob.custom_time = modified
    pb_blob.upload_from_string(
        vulnerability.SerializeToString(deterministic=True),
        content_type='application/octet-stream',
        if_generation_match=pb_generation)
  except Exception:
    logging.exception('failed to upload %s protobuf to GCS', vuln_id)
    # TODO(michaelkedar): send pub/sub message to retry

  try:
    json_blob = bucket.blob(os.path.join(VULN_JSON_PATH, vuln_id + '.json'))
    json_blob.custom_time = modified
    json_data = json_format.MessageToJson(
        vulnerability, preserving_proto_field_name=True, indent=None)
    json_blob.upload_from_string(json_data, content_type='application/json')
  except Exception:
    logging.exception('failed to upload %s protobuf to GCS', vuln_id)
    # TODO(michaelkedar): send pub/sub message to retry
