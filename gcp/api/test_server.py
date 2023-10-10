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

  def check(self):
    """Check that the server is still up."""
    if self.backend.poll():
      raise RuntimeError('Backend process died.')

    if self.esp.poll():
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


def get_ip():
  """Get IP."""
  result = subprocess.run([
      'hostname',
      '-i',
  ], capture_output=True, check=True)
  ip = result.stdout.decode().strip()
  print('Got cloudbuild host', ip)
  return ip


def start_esp(port, backend_port, credential_path, log_path):
  """Start ESPv2 frontend."""
  log_handle = open(log_path, 'w')

  if os.getenv('CLOUDBUILD'):
    network = '--network=cloudbuild'
    host = get_ip()
    docker_image = 'gcr.io/endpoints-release/endpoints-runtime:2'
    # Use standard endpoints container and GCP credentials.
    docker_cmd = [
        'docker',
        'run',
        '--name',
        'osv-esp',
        network,
        '--rm',
        '-v',
        f'--publish={port}',
        f'{docker_image}',
        '--disable_tracing',
        '--service=api-test.osv.dev',
        '--rollout_strategy=managed',
        f'--listener_port={port}',
        f'--backend=grpc://{host}:{backend_port}',
        '--enable_debug',
        '--transcoding_preserve_proto_field_names',
        '--envoy_connection_buffer_limit_bytes=10485760',
    ]
  else:
    # Use custom container and local ADC credential by mapping files
    # into container.
    credential_dir = os.path.dirname(os.path.abspath(credential_path))
    credential_name = os.path.basename(credential_path)
    network = '--network=host'
    host = 'localhost'
    docker_image = 'osv/esp:latest'
    docker_cmd = [
        'docker',
        'run',
        '--name',
        'osv-esp',
        network,
        '--rm',
        '-v',
        f'{credential_dir}:/esp:ro',
        f'--publish={port}',
        f'{docker_image}',
        '--disable_tracing',
        '--service=api-test.osv.dev',
        '--rollout_strategy=managed',
        f'--listener_port={port}',
        f'--backend=grpc://{host}:{backend_port}',
        f'--service_account_key=/esp/{credential_name}',
        '--non_gcp',
        '--enable_debug',
        '--transcoding_preserve_proto_field_names',
        '--envoy_connection_buffer_limit_bytes=10485760',
    ]

  # Stop existing osv-esp processes that weren't killed properly.
  subprocess.run(['docker', 'stop', 'osv-esp'], check=False)
  esp_proc = subprocess.Popen(
      docker_cmd, stdout=log_handle, stderr=subprocess.STDOUT)
  return esp_proc


def start(credential_path, port=_ESP_PORT, backend_port=_BACKEND_PORT):
  """Start the test server."""
  backend = None
  esp = None
  try:
    backend = start_backend(_BACKEND_PORT, 'backend.log')
    esp = start_esp(port, backend_port, credential_path, 'esp.log')
  except Exception:
    if esp:
      esp.kill()

    if backend:
      backend.kill()

    raise

  return ServerInstance(backend, esp)


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} path/to/credential.json')
    sys.exit(1)

  server = start(sys.argv[1])
  try:
    while True:
      server.check()
      time.sleep(5)
  finally:
    server.stop()
