# Copyright 2021 Google LLC
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
"""Test helpers."""
import datetime
import os
import pprint
import requests
import subprocess
import tempfile
import threading
from unittest import mock

import pygit2

_EMULATOR_TIMEOUT = 30
_DATASTORE_EMULATOR_PORT = 8002
_DATASTORE_READY_INDICATOR = b'is now running'
TEST_PROJECT_ID = 'test-osv'


def ExpectationTest(test_data_dir):  # pylint: disable=invalid-name
  """Mixin for test output generation/comparison."""

  class Mixin:
    """Mixin."""

    def _load_expected(self, expected_name, actual):
      """Load expected data."""
      expected_path = os.path.join(
          test_data_dir, f'{self.__class__.__name__}_{expected_name}.txt')
      if os.getenv('TESTS_GENERATE'):
        pp = pprint.PrettyPrinter(indent=4)
        with open(expected_path, 'w') as f:
          f.write(pp.pformat(actual))

      with open(expected_path) as f:
        return eval(f.read())  # pylint: disable=eval-used

    def expect_dict_equal(self, expected_name, actual):
      """Check if the output dict is equal to the expected value."""
      self.assertDictEqual(self._load_expected(expected_name, actual), actual)

    def expect_equal(self, expected_name, actual):
      """Check if the output is equal to the expected value."""
      self.assertEqual(self._load_expected(expected_name, actual), actual)

  return Mixin


class MockRepo:
  """Mock repo."""

  def __init__(self, path):
    self.path = path
    self._repo = pygit2.init_repository(path, True)
    tree = self._repo.TreeBuilder().write()
    author = pygit2.Signature('OSV', 'infra@osv.dev')
    self._repo.create_commit('HEAD', author, author, 'Initial commit', tree, [])

  def add_file(self, path, contents):
    """Adds a file."""
    oid = self._repo.write(pygit2.GIT_OBJ_BLOB, contents)
    self._repo.index.add(pygit2.IndexEntry(path, oid, pygit2.GIT_FILEMODE_BLOB))
    self._repo.index.write()

  def delete_file(self, path):
    """Delete a file."""
    self._repo.index.remove(path)
    self._repo.index.write()

  def commit(self, author_name, author_email, message='Changes'):
    """Makes a commit."""
    tree = self._repo.index.write_tree()
    author = pygit2.Signature(author_name, author_email)
    self._repo.create_commit('HEAD', author, author, message, tree,
                             [self._repo.head.peel().oid])


def start_datastore_emulator():
  """Starts Datastore emulator."""
  os.environ['DATASTORE_EMULATOR_HOST'] = 'localhost:' + str(
      _DATASTORE_EMULATOR_PORT)
  os.environ['DATASTORE_PROJECT_ID'] = TEST_PROJECT_ID
  os.environ['GOOGLE_CLOUD_PROJECT'] = TEST_PROJECT_ID
  proc = subprocess.Popen([
      'gcloud',
      'beta',
      'emulators',
      'datastore',
      'start',
      '--consistency=1.0',
      '--host-port=localhost:' + str(_DATASTORE_EMULATOR_PORT),
      '--project=' + TEST_PROJECT_ID,
      '--no-store-on-disk',
  ],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)

  _wait_for_emulator_ready(proc, 'datastore', _DATASTORE_READY_INDICATOR)
  return proc


def _wait_for_emulator_ready(proc,
                             emulator,
                             indicator,
                             timeout=_EMULATOR_TIMEOUT):
  """Waits for emulator to be ready."""

  def _read_thread(proc, ready_event):
    """Thread to continuously read from the process stdout."""
    ready = False
    while True:
      line = proc.stdout.readline()
      if not line:
        break

      if not ready and indicator in line:
        ready = True
        ready_event.set()

  # Wait for process to become ready.
  ready_event = threading.Event()
  thread = threading.Thread(target=_read_thread, args=(proc, ready_event))
  thread.daemon = True
  thread.start()

  if not ready_event.wait(timeout):
    raise RuntimeError(
        '{} emulator did not get ready in time.'.format(emulator))

  return thread


def reset_emulator():
  """Resets emulator."""
  resp = requests.post(
      'http://localhost:{}/reset'.format(_DATASTORE_EMULATOR_PORT))
  resp.raise_for_status()


def mock_datetime(test):
  """Mocks datetime."""
  for to_mock in ('osv.models.utcnow', 'osv.utcnow'):
    patcher = mock.patch(to_mock)
    mock_utcnow = patcher.start()
    mock_utcnow.return_value = datetime.datetime(2021, 1, 1)
    test.addCleanup(patcher.stop)


def mock_repository(test):
  """Creates a mock repo."""
  tmp_dir = tempfile.TemporaryDirectory()
  test.remote_source_repo_path = tmp_dir.name
  test.addCleanup(tmp_dir.cleanup)
  return MockRepo(test.remote_source_repo_path)


def mock_clone(test, func=None, return_value=None):
  """Mocks clone_repository."""
  patcher = mock.patch('osv.repos.clone')
  mocked = patcher.start()
  if return_value:
    mocked.return_value = return_value
  else:
    mocked.side_effect = func
  test.addCleanup(patcher.stop)
