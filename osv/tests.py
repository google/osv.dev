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
"""Test helpers."""
import contextlib
import datetime
import difflib
import os
import pprint
import signal
import time

from proto import datetime_helpers
import requests
import subprocess
import tempfile
from unittest import mock

import pygit2
import pygit2.enums

from . import gcs_mock

_EMULATOR_TIMEOUT = 30
_DATASTORE_EMULATOR_PORT = '8002'
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
        eval_globals = globals()
        eval_globals['call'] = mock.call
        eval_globals['DatetimeWithNanoseconds'] = datetime_helpers.DatetimeWithNanoseconds  # pylint: disable=line-too-long
        return eval(f.read(), eval_globals)  # pylint: disable=eval-used

    def expect_dict_equal(self, expected_name, actual):
      """Check if the output dict is equal to the expected value."""
      self.assertDictEqual(self._load_expected(expected_name, actual), actual)

    def expect_lines_equal(self, expected_name, actual_lines):
      """Check if the output lines is equal to the expected value,
      printing a diff when it is different."""
      expected_lines = self._load_expected(expected_name, actual_lines)
      if expected_lines != actual_lines:
        diff = difflib.unified_diff(expected_lines, actual_lines, 'expected',
                                    'actual')
        print(''.join(diff))
        self.fail()

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
    oid = self._repo.write(pygit2.enums.ObjectType.BLOB, contents)
    self._repo.index.add(
        pygit2.IndexEntry(path, oid, pygit2.enums.FileMode.BLOB))
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
                             [self._repo.head.peel().id])


class _DatastoreEmulator:

  def __init__(self, url):
    self._url = url

  def reset(self):
    """Clear emulator data."""
    resp = requests.post(f'http://{self._url}/reset', timeout=_EMULATOR_TIMEOUT)
    resp.raise_for_status()


def _is_emulator_installed():
  """Check if the gcloud firestore emulator is installed."""
  try:
    # We check if the component is installed.
    output = subprocess.check_output([
        'gcloud', 'components', 'list', '--quiet',
        '--filter=id:cloud-firestore-emulator', '--format=value(state.name)'
    ],
                                     text=True,
                                     stderr=subprocess.DEVNULL)
    return 'Not Installed' not in output
  except (subprocess.CalledProcessError, FileNotFoundError):
    return False


@contextlib.contextmanager
def datastore_emulator():
  """A context for running the datastore emulator in."""
  if not _is_emulator_installed():
    raise RuntimeError(
        'gcloud firestore emulator is not installed or not working. '
        'Please install it by running '
        '`gcloud components install cloud-firestore-emulator` and/or '
        'ensure `gcloud` is in your PATH.')

  port = os.environ.get('DATASTORE_EMULATOR_PORT', _DATASTORE_EMULATOR_PORT)
  env = {
      'DATASTORE_EMULATOR_HOST': 'localhost:' + port,
      'DATASTORE_PROJECT_ID': TEST_PROJECT_ID,
      'GOOGLE_CLOUD_PROJECT': TEST_PROJECT_ID,
  }
  old_env = {}
  for k, v in env.items():
    old_env[k] = os.environ.get(k)
    os.environ[k] = v

  url = f'localhost:{port}'
  # Try shutdown an existing emulator on the port
  try:
    requests.post(f'http://{url}/shutdown', timeout=_EMULATOR_TIMEOUT)
  except requests.ConnectionError:
    pass

  # Start the emulator in a new process group so we can terminate the
  # subprocesses it spawns.
  emu = subprocess.Popen([
      'gcloud',
      'emulators',
      'firestore',
      'start',
      '--database-mode=datastore-mode',
      f'--host-port={url}',
  ],
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL,
                         start_new_session=True)

  # Wait for ready
  start = time.time()
  while time.time() - start < _EMULATOR_TIMEOUT:
    try:
      resp = requests.get(f'http://{url}', timeout=_EMULATOR_TIMEOUT)
      if resp.ok:
        break
    except requests.ConnectionError:
      pass
    time.sleep(0.5)
  else:
    os.killpg(emu.pid, signal.SIGKILL)
    raise RuntimeError('Datastore emulator did not get ready in time.')

  # Also mock the GCS bucket
  with gcs_mock.gcs_mock():
    yield _DatastoreEmulator(url)

  # Stop the process
  requests.post(f'http://{url}/shutdown', timeout=_EMULATOR_TIMEOUT)
  try:
    os.killpg(emu.pid, signal.SIGTERM)
    emu.wait(timeout=_EMULATOR_TIMEOUT)
  except subprocess.TimeoutExpired:
    print('Emulator ignored SIGTERM. Sending SIGKILL')
    os.killpg(emu.pid, signal.SIGKILL)
    emu.wait()
  finally:
    # restore environment variables
    for k, v in old_env.items():
      if v is None:
        os.environ.pop(k, None)
      else:
        os.environ[k] = v


def mock_datetime(test):
  """Mocks datetime."""
  for to_mock in ('osv.models.utcnow', 'osv.utcnow'):
    patcher = mock.patch(to_mock)
    mock_utcnow = patcher.start()
    mock_utcnow.return_value = datetime.datetime(
        2021, 1, 1, tzinfo=datetime.UTC)
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
