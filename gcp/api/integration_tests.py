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
"""API server integration tests."""

import json
import os
import sys
import subprocess
import time
import unittest

import requests

import test_server

_PORT = 8080


def _api():
  if os.getenv('CLOUDBUILD'):
    host = test_server.get_cloudbuild_esp_host()
  else:
    host = 'localhost'

  return f'http://{host}:{_PORT}'


class IntegrationTests(unittest.TestCase):
  """Server integration tests."""

  _VULN_744 = {
      'affects': {
          'ranges': [{
              'fixedIn': {
                  'commit': '97319697c8f9f6ff27b32589947e1918e3015503',
                  'repoType': 'GIT',
                  'repoUrl': 'https://github.com/mruby/mruby'
              },
              'introducedIn': {
                  'commit': '9cdf439db52b66447b4e37c61179d54fad6c8f33',
                  'repoType': 'GIT',
                  'repoUrl': 'https://github.com/mruby/mruby'
              },
          },],
          'versions': ['2.1.2', '2.1.2-rc', '2.1.2-rc2']
      },
      'details': 'OSS-Fuzz report: '
                 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801\n'
                 '\n'
                 'Crash type: Heap-double-free\n'
                 'Crash state:\n'
                 'mrb_default_allocf\n'
                 'mrb_free\n'
                 'obj_free\n',
      'id': 'OSV-2020-744',
      'package': {
          'name': 'mruby'
      },
      'referenceUrls': [
          'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801'
      ],
      'severity': 'HIGH',
      'summary': 'Heap-double-free in mrb_default_allocf'
  }

  _VULN_2258 = {
      'details': 'INVALID',
      'id': 'OSV-2020-2258',
      'package': {
          'name': 'grok'
      },
      'referenceUrls': [
          'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=28505'
      ],
      'summary': 'Heap-buffer-overflow in grk::t1_part1::T1Part1::decompress'
  }

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def test_get(self):
    """Test getting a vulnerability."""
    response = requests.get(_api() + '/v1/vulns/2020-744')
    self.assertDictEqual(self._VULN_744, response.json())

    response = requests.get(_api() + '/v1/vulns/OSV-2020-744')
    self.assertDictEqual(self._VULN_744, response.json())

  def test_get_invalid(self):
    """Test getting an invalid vulnerability."""
    response = requests.get(_api() + '/v1/vulns/OSV-2020-2258')
    self.assertDictEqual(self._VULN_2258, response.json())

  def test_query_commit(self):
    """Test querying by commit."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'commit': '233cb49903fa17637bd51f4a16b4ca61e0750f24',
        }))
    self.assertDictEqual({'vulns': [self._VULN_744]}, response.json())

  def test_query_version(self):
    """Test querying by version."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '2.1.2rc',
            'package': {
                'name': 'mruby',
            }
        }))
    self.assertDictEqual({'vulns': [self._VULN_744]}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '2.1.2-rc',
            'package': {
                'name': 'mruby',
            }
        }))
    self.assertDictEqual({'vulns': [self._VULN_744]}, response.json())


def print_logs(filename):
  """Print logs."""
  if not os.path.exists(filename):
    return

  print(filename + ':')
  with open(filename) as f:
    print(f.read())


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print(f'Usage: {sys.argv[0]} path/to/service_account.json')
    sys.exit(1)

  subprocess.run(
      ['docker', 'pull', 'gcr.io/endpoints-release/endpoints-runtime:2'],
      check=True)

  service_account_path = sys.argv.pop()
  server = test_server.start(service_account_path, port=_PORT)
  time.sleep(30)

  try:
    unittest.main()
  finally:
    server.stop()

    print_logs('esp.log')
    print_logs('backend.log')
