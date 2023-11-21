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

from google.cloud.datastore_admin_v1.services.datastore_admin import client \
    as ds_admin

_PROJECT = 'oss-vdb-test'
_BACKUP_BUCKET = 'osv-backup'


def main():
  """Create a Datastore backup."""
  client = ds_admin.DatastoreAdminClient()
  client.export_entities(
      project_id=_PROJECT, output_url_prefix=f'gs://testing-{_BACKUP_BUCKET}')

  return True
