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
"""Linter findings API."""

import json
import logging
from flask import Blueprint, abort, jsonify
from google.cloud import storage

blueprint = Blueprint('linter_api', __name__, url_prefix='/linter-findings')

# TODO: Make this configurable if needed, but for now it matches linter.py
LINTER_BUCKET = 'osv-test-public-import-logs'
LINTER_PREFIX = 'linter-result/'


def _get_storage_client():
  return storage.Client()


@blueprint.route('/')
def list_sources():
  """List all sources that have linter findings."""
  client = _get_storage_client()
  try:
    bucket = client.bucket(LINTER_BUCKET)
    # List blobs with the prefix.
    # We want to emulate "directories" here.
    # The structure is linter-result/<source>/result.json
    # So we list with delimiter='/'
    blobs = client.list_blobs(
        LINTER_BUCKET, prefix=LINTER_PREFIX, delimiter='/')
    
    # Iterate to populate prefixes (folders)
    # Note: list_blobs is lazy, so we must iterate or call list() to populate prefixes
    list(blobs)
    
    sources = []
    for prefix in blobs.prefixes:
      # prefix is something like 'linter-result/source-name/'
      # we want 'source-name'
      stripped = prefix.removeprefix(LINTER_PREFIX).removesuffix('/')
      if stripped:
        sources.append(stripped)
        
    return jsonify(sources)
  except Exception as e:
    logging.error('Failed to list linter sources: %s', e)
    abort(500, description="Failed to list sources")


@blueprint.route('/<source>')
def get_findings(source):
  """Get linter findings for a specific source."""
  client = _get_storage_client()
  try:
    bucket = client.bucket(LINTER_BUCKET)
    blob_path = f'{LINTER_PREFIX}{source}/result.json'
    blob = bucket.blob(blob_path)
    
    if not blob.exists():
      abort(404, description=f"No findings found for source: {source}")
      
    content = blob.download_as_text()
    return jsonify(json.loads(content))
  except json.JSONDecodeError:
    logging.error('Invalid JSON in linter findings for %s', source)
    abort(500, description="Invalid findings data")
  except Exception as e:
    # Check if it was an abort(404) from above, re-raise if so
    if hasattr(e, 'code') and e.code == 404:
      raise e
    logging.error('Failed to get linter findings for %s: %s', source, e)
    abort(500, description="Failed to retrieve findings")
