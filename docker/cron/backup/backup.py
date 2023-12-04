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

import os
import sys
from google.cloud import ndb
from google.cloud.datastore_admin_v1.services.datastore_admin import client \
    as ds_admin

import osv.logs


def main():
  """Create a Datastore backup."""
  client = ds_admin.DatastoreAdminClient()
  backup_bucket = os.environ['BACKUP_BUCKET']
  project_id = os.environ['GOOGLE_CLOUD_PROJECT']
  client.export_entities(
      project_id=project_id, output_url_prefix=f'gs://{backup_bucket}')

  return 0


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('backup')
  with _ndb_client.context():
    sys.exit(main())
