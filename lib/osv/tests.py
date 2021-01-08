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
import os
import requests
import subprocess
import threading

_EMULATOR_TIMEOUT = 30
_DATASTORE_EMULATOR_PORT = 8002
_DATASTORE_READY_INDICATOR = b'is now running'
TEST_PROJECT_ID = 'test-osv'


def start_datastore_emulator():
  """Start Datastore emulator."""
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
  ], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

  _wait_for_emulator_ready(proc, 'datastore', _DATASTORE_READY_INDICATOR)
  return proc


def _wait_for_emulator_ready(proc,
                             emulator,
                             indicator,
                             timeout=_EMULATOR_TIMEOUT):
  """Wait for emulator to be ready."""

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
  """Reset emulator."""
  resp = requests.post(
      'http://localhost:{}/reset'.format(_DATASTORE_EMULATOR_PORT))
  resp.raise_for_status()
