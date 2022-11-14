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
"""Start a test API server."""

import os
import subprocess
import sys
import time

_ESP_PORT = 8080
_BACKEND_PORT = 8000
_GCP_PROJECT = 'oss-vdb'


class ServerInstance:
  """Server instance."""

  def __init__(self, backend, esp):
    self.backend = backend
    self.esp = esp

  def _emit_log(self, log_path):
    """If log_path is non-zero length, display it."""
    statinfo = os.stat(log_path)
    if statinfo.st_size > 0:
      print('{} contents:'.format(log_path))
      with open(log_path) as log_handle:
        while True:
          line = log_handle.readline()
          if not line:
            break
          print('{}'.format(line.strip()))

  def check(self):
    """Check that the server is still up."""
    if self.backend.poll():
      self._emit_log('backend.log')
      raise RuntimeError('Backend process died.')

    if self.esp.poll():
      self._emit_log('esp.log')
      raise RuntimeError('ESP process died.')

  def stop(self):
    """Stop the server."""
    self.esp.kill()
    self.backend.kill()


def start_backend(port, log_path):
  """Start backend server."""
  log_handle = open(log_path, 'w')
  env = os.environ.copy()
  env['GOOGLE_CLOUD_PROJECT'] = _GCP_PROJECT

  backend_proc = subprocess.Popen(
      [sys.executable, 'server.py', f'--port={port}'],
      env=env,
      stdout=log_handle,
      stderr=subprocess.STDOUT)

  return backend_proc


def get_cloudbuild_esp_host():
  """Get cloudbuild host."""
  result = subprocess.run([
      'docker', 'inspect', 'osv-esp',
      '--format={{(index .NetworkSettings.Networks "cloudbuild").IPAddress}}'
  ],
                          capture_output=True,
                          check=True)
  ip = result.stdout.decode().strip()
  print('Got cloudbuild ESP host', ip)
  return ip


def docker_inspect():
  """Convenience function to troubleshoot running Docker container."""
  result = subprocess.run(['docker', 'inspect', 'osv-esp'],
                          capture_output=True,
                          check=True)
  print('This is what we know about the Docker container')
  print(result)


def get_ip():
  """Get IP."""
  result = subprocess.run([
      'hostname',
      '-i',
  ], capture_output=True, check=True)
  ip = result.stdout.decode().strip()
  print('Got cloudbuild host', ip)
  return ip


def start_esp(port, backend_port, log_path):
  """Start ESPv2 frontend."""
  log_handle = open(log_path, 'w')

  if os.getenv('CLOUDBUILD'):
    network = '--network=cloudbuild'
    host = get_ip()
  else:
    network = '--network=host'
    host = 'localhost'

  # Stop existing osv-esp processes that weren't killed properly.
  subprocess.run(['docker', 'stop', 'osv-esp'], check=False)
  esp_proc = subprocess.Popen([
      'docker',
      'run',
      '--privileged',
      '--name',
      'osv-esp',
      network,
      '--rm',
      f'--publish={port}',
      'gcr.io/endpoints-release/endpoints-runtime:2',
      '--disable_tracing',
      '--service=api-test.osv.dev',
      '--rollout_strategy=managed',
      f'--listener_port={port}',
      f'--backend=grpc://{host}:{backend_port}',
      '--enable_debug',
      '--transcoding_preserve_proto_field_names',
      '--envoy_connection_buffer_limit_bytes=10485760',
  ],
                              stdout=log_handle,
                              stderr=subprocess.STDOUT)
  return esp_proc


def start(port=_ESP_PORT, backend_port=_BACKEND_PORT):
  """Start the test server."""
  backend = None
  esp = None
  try:
    backend = start_backend(backend_port, 'backend.log')
    esp = start_esp(port, backend_port, 'esp.log')
  except Exception:
    if esp:
      esp.kill()

    if backend:
      backend.kill()

    raise

  return ServerInstance(backend, esp)


if __name__ == '__main__':
  server = start()
  try:
    while True:
      server.check()
      time.sleep(5)
  finally:
    server.stop()
