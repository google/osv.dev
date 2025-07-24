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
"""Functions for mocking the GCS bucket for testing."""
import contextlib
import datetime
import os
import pathlib
import tempfile
from typing import Optional
from unittest import mock

from . import gcs


@contextlib.contextmanager
def gcs_mock(directory: Optional[str] = None):
  """A context for mocking reads/writes to the vulnerabilities GCS bucket.
  
  If `directory` is set, blobs will be read from/written to files in the
  directory, which will remain after the context exits.
  Otherwise, blobs will be written to a temporary directory, which is deleted
  when the context exits.
  """
  with (tempfile.TemporaryDirectory()
        if directory is None else contextlib.nullcontext(directory)) as db_dir:
    pathlib.Path(db_dir, gcs.VULN_JSON_PATH).mkdir(parents=True, exist_ok=True)
    pathlib.Path(db_dir, gcs.VULN_PB_PATH).mkdir(parents=True, exist_ok=True)
    bucket = _MockBucket(db_dir)
    with mock.patch('osv.gcs.get_osv_bucket', return_value=bucket):
      yield db_dir


class _MockBucket:
  """Mock google.cloud.storage.Bucket with only necessary methods for tests."""

  def __init__(self, db_dir: str):
    self._db_dir = db_dir

  def blob(self, blob_name: str):
    return _MockBlob(os.path.join(self._db_dir, blob_name))


class _MockBlob:
  """Mock google.cloud.storage.Blob with only necessary methods for tests."""

  def __init__(self, path: str):
    self._path = path
    self.custom_time: Optional[datetime.datetime] = None

  def upload_from_string(self, data: str | bytes, content_type: str):
    """Implements google.cloud.storage.Blob.upload_from_string."""
    del content_type  # Can't do anything with this.
    if isinstance(data, str):
      data = data.encode()
    with open(self._path, 'wb') as f:
      f.write(data)

    # Use the file's modified time to store the CustomTime metadata.
    if self.custom_time is not None:
      ts = self.custom_time.timestamp()
      os.utime(self._path, (ts, ts))
