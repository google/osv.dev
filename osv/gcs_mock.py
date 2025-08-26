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
from collections import defaultdict
import contextlib
import datetime
import os
import pathlib
import tempfile
from typing import Any
from unittest import mock

from google.cloud import exceptions

from . import gcs


@contextlib.contextmanager
def gcs_mock(directory: str | None = None):
  """A context for mocking reads/writes to the vulnerabilities GCS bucket.
  
  If `directory` is set, blobs will be read from/written to files in the
  directory, which will remain after the context exits.
  Otherwise, blobs will be written to a temporary directory, which is deleted
  when the context exits.
  """
  with (tempfile.TemporaryDirectory()
        if directory is None else contextlib.nullcontext(directory)) as db_dir:
    pathlib.Path(db_dir, gcs.VULN_PB_PATH).mkdir(parents=True, exist_ok=True)
    bucket = _MockBucket(db_dir)
    with mock.patch(
        'osv.gcs.get_osv_bucket',
        return_value=bucket), mock.patch('osv.pubsub.publish_failure'):
      yield db_dir


class _MockBlob:
  """Mock google.cloud.storage.Blob with only necessary methods for tests."""

  def __init__(self, path: str, generations: dict[str, int] = None):
    self._path = path
    self.custom_time: datetime.datetime | None = None
    # store a reference to all the blob generations
    self._generations = generations

  def upload_from_string(self,
                         data: str | bytes,
                         content_type: str | None = None,
                         if_generation_match: Any | None = None):
    """Implements google.cloud.storage.Blob.upload_from_string."""
    del content_type  # Can't do anything with this.

    if if_generation_match not in (None, self._generations[self._path]):
      raise exceptions.PreconditionFailed('Generation mismatch')

    if isinstance(data, str):
      data = data.encode()
    with open(self._path, 'wb') as f:
      f.write(data)
    self._generations[self._path] += 1

    # Use the file's modified time to store the CustomTime metadata.
    if self.custom_time is not None:
      ts = self.custom_time.timestamp()
      os.utime(self._path, (ts, ts))

  def download_as_bytes(self) -> bytes:
    """Implements google.cloud.storage.Blob.download_as_bytes."""
    try:
      with open(self._path, 'rb') as f:
        return f.read()
    except FileNotFoundError as exc:
      raise exceptions.NotFound(self._path) from exc


class _MockBucket:
  """Mock google.cloud.storage.Bucket with only necessary methods for tests."""

  def __init__(self, db_dir: str):
    self._db_dir = db_dir
    self._generations = defaultdict(int)
    # Create a generation for any pre-existing files
    for root, _, blobs in os.walk(self._db_dir):
      for blob_name in blobs:
        self._generations[os.path.join(root, blob_name)] = 1

  def blob(self, blob_name: str) -> _MockBlob:
    return _MockBlob(os.path.join(self._db_dir, blob_name), self._generations)

  def get_blob(self, blob_name: str) -> _MockBlob | None:
    path = os.path.join(self._db_dir, blob_name)
    if not os.path.exists(path):
      return None
    blob = _MockBlob(path, self._generations)
    ts = os.path.getmtime(path)
    blob.custom_time = datetime.datetime.fromtimestamp(ts, datetime.UTC)
    blob.generation = self._generations[path]
    return blob
