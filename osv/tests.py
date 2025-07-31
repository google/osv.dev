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
import difflib
import os
import pprint
import signal

from proto import datetime_helpers
import requests
import subprocess
import tempfile
import threading
from unittest import mock

import pygit2
import pygit2.enums

from . import gcs_mock

_EMULATOR_TIMEOUT = 30
_DATASTORE_EMULATOR_PORT = '8002'
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


_ds_data_dir = None

_mock_gcs_ctx = None


def start_datastore_emulator():
  """Starts Datastore emulator."""
  # TODO(michaelkedar): turn this into a context (`with datastore_emulator()`)
  _kill_existing_datastore_emulator()

  port = os.environ.get('DATASTORE_EMULATOR_PORT', _DATASTORE_EMULATOR_PORT)
  os.environ['DATASTORE_EMULATOR_HOST'] = 'localhost:' + port
  os.environ['DATASTORE_PROJECT_ID'] = TEST_PROJECT_ID
  os.environ['GOOGLE_CLOUD_PROJECT'] = TEST_PROJECT_ID
  global _ds_data_dir
  _ds_data_dir = tempfile.TemporaryDirectory()
  # TODO(michaelkedar): use `gcloud emulators firestore` with
  # `--database-mode=datastore-mode` instead.
  proc = subprocess.Popen([
      'gcloud',
      'beta',
      'emulators',
      'datastore',
      'start',
      '--host-port=localhost:' + port,
      '--project=' + TEST_PROJECT_ID,
      '--no-store-on-disk',
      f'--data-dir={_ds_data_dir.name}',
      '--use-firestore-in-datastore-mode',
  ],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)

  _wait_for_emulator_ready(proc, 'datastore', _DATASTORE_READY_INDICATOR)

  # Also mock the GCS bucket.
  global _mock_gcs_ctx
  _mock_gcs_ctx = gcs_mock.gcs_mock()
  _mock_gcs_ctx.__enter__()  # pylint: disable=unnecessary-dunder-call

  return proc


def _kill_existing_datastore_emulator():
  """
     Finds and kills the Google Cloud Datastore emulator process.

     This function executes `ps x`, searches for the process line containing
     'com.google.cloud.datastore.emulator.CloudDatastore start' and '--port=',
     extracts the PID, and sends a SIGKILL signal to terminate it.
     """
  try:
    # 1. Execute `ps x` to get a list of processes and their commands.
    # The output is captured as a byte string.
    process_list_output = subprocess.check_output(['ps', 'x'])
  except (subprocess.CalledProcessError, FileNotFoundError) as e:
    print(f'Error executing "ps x": {e}')
    return

  # 2. Decode the byte string to a UTF-8 string and split into individual lines.
  lines = process_list_output.decode('utf-8').strip().split('\n')

  # 3. Define the unique strings that identify the target process.
  target_string_1 = 'com.google.cloud.datastore.emulator.CloudDatastore start'
  target_string_2 = f'--port={_DATASTORE_EMULATOR_PORT}'

  # 4. Go through each line of the process list.
  for line in lines:
    # 5. Check if the line contains both of our target strings.
    if target_string_1 in line and target_string_2 in line:
      print(f'Found target process line: {line.strip()}')
      try:
        # 6. Extract the PID. The PID is the first column in the `ps x` output.
        # We split the line by whitespace and take the first element.
        pid_str = line.strip().split()[0]
        pid = int(pid_str)

        # 7. Kill the process using its PID.
        print(f'Attempting to terminate process with PID: {pid}')
        os.kill(pid, signal.SIGTERM)
        print(f'Successfully sent SIGTERM to process {pid}.')
        # Once we've found and killed the process, we can stop searching.
        break
      except (ValueError, IndexError):
        print(f'Could not parse PID from line: {line.strip()}')
      except ProcessLookupError:
        # This can happen if the process terminated
        # between finding it and trying to kill it.
        print(f'Process with PID {pid} not found. '
              f'It might have already been terminated.')
      except PermissionError:
        print(f'Permission denied. Could not terminate process {pid}.')
      except Exception as e:
        print(f'An unexpected error occurred while '
              f'trying to kill process {pid}: {e}')


emulator_stdout_thread_output = ''


def _wait_for_emulator_ready(proc,
                             emulator,
                             indicator,
                             timeout=_EMULATOR_TIMEOUT):
  """Waits for emulator to be ready."""
  global emulator_stdout_thread_output
  emulator_stdout_thread_output = ''

  def _read_thread(proc, ready_event):
    """Thread to continuously read from the process stdout."""
    global emulator_stdout_thread_output
    ready = False
    while True:
      line = proc.stdout.readline()
      if not line:
        break
      emulator_stdout_thread_output += str(line) + '\n'

      if not ready and indicator in line:
        ready = True
        ready_event.set()

  # Wait for process to become ready.
  ready_event = threading.Event()
  thread = threading.Thread(target=_read_thread, args=(proc, ready_event))
  thread.daemon = True
  thread.start()

  if not ready_event.wait(timeout):
    print(emulator_stdout_thread_output)
    raise RuntimeError(
        '{} emulator did not get ready in time.'.format(emulator))

  return thread


def reset_emulator():
  """Resets emulator."""
  port = os.environ.get('DATASTORE_EMULATOR_PORT', _DATASTORE_EMULATOR_PORT)
  resp = requests.post(
      'http://localhost:{}/reset'.format(port), timeout=_EMULATOR_TIMEOUT)
  resp.raise_for_status()


def stop_emulator():
  """Stops emulator."""
  global _mock_gcs_ctx
  if _mock_gcs_ctx is not None:
    _mock_gcs_ctx.__exit__(None, None, None)
  _mock_gcs_ctx = None

  try:
    port = os.environ.get('DATASTORE_EMULATOR_PORT', _DATASTORE_EMULATOR_PORT)
    resp = requests.post(
        'http://localhost:{}/shutdown'.format(port), timeout=_EMULATOR_TIMEOUT)
    resp.raise_for_status()
    global _ds_data_dir
    if _ds_data_dir:
      _ds_data_dir.cleanup()
      _ds_data_dir = None
  except Exception as e:
    # Something went wrong, manually kill all datastore processes instead.
    os.system('pkill -f datastore')
    raise e


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
