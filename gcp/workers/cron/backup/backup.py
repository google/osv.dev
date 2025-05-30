#!/usr/bin/env python3
# Copyright 2023 Google LLC
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
"""Datastore backup."""

from __future__ import annotations

import os
import sys

from google.cloud import ndb
from google.cloud import datastore_admin_v1 # For datastore_admin_v1.types
# ds_admin is an alias for the client module itself
from google.cloud.datastore_admin_v1.services import datastore_admin
# For type hinting the client instance, use the specific class from the module:
# from google.cloud.datastore_admin_v1.services.datastore_admin.client import DatastoreAdminClient
# However, the original code used `ds_admin.DatastoreAdminClient()`.
# Let's keep ds_admin alias if it's for the module, or import class directly.
# The original import `from google.cloud.datastore_admin_v1.services.datastore_admin import client as ds_admin`
# means ds_admin refers to the client module. So ds_admin.DatastoreAdminClient is correct.

import osv.logs # osv.logs.setup_gcp_logging

# Global NDB client, initialized in __main__
_ndb_client: ndb.Client


def main() -> int:
  """Create a Datastore backup."""
  # Client type from the aliased module or direct import
  client: datastore_admin.DatastoreAdminClient = datastore_admin.DatastoreAdminClient()

  backup_bucket: str = os.environ['BACKUP_BUCKET']
  affected_commits_backup_bucket: str = os.environ['AFFECTED_COMMITS_BACKUP_BUCKET']
  project_id: str = os.environ['GOOGLE_CLOUD_PROJECT']

  # Export all entities (except AffectedCommits, if they are large and handled separately)
  # The API call is a long-running operation, but this script doesn't wait for it.
  client.export_entities(
      project_id=project_id,
      output_url_prefix=f'gs://{backup_bucket}'
      # entity_filter can be used to exclude kinds if needed
  )
  logging.info("Initiated export of all entities to gs://%s", backup_bucket)

  # Export AffectedCommits entities specifically
  # Use datastore_admin_v1.types for EntityFilter
  entity_filter = datastore_admin_v1.types.EntityFilter()
  entity_filter.kinds = ['AffectedCommits']

  client.export_entities(
      project_id=project_id,
      output_url_prefix=f'gs://{affected_commits_backup_bucket}',
      entity_filter=entity_filter
  )
  logging.info("Initiated export of AffectedCommits to gs://%s", affected_commits_backup_bucket)

  return 0


if __name__ == '__main__':
  # Initialize NDB client for the script's context
  _ndb_client = ndb.Client()
  # Setup logging (assuming it might use NDB or GCP context)
  osv.logs.setup_gcp_logging('backup') # project_id will be inferred

  # Run main function within NDB context
  # This is primarily for scripts that might directly use NDB operations,
  # though this backup script uses DatastoreAdminClient which might not strictly need it.
  # However, keeping it if osv.logs.setup_gcp_logging or other parts might use NDB context.
  with _ndb_client.context():
    # It's good practice for main() to return status, and sys.exit to use it.
    # If main() raises unhandled exceptions, script will exit non-zero.
    # If it completes and returns 0, script exits 0.
    return_code = main()
    sys.exit(return_code)
