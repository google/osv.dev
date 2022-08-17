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
      'published': '2020-07-04T00:00:01.948828Z',
      'schema_version': '1.2.0',
      'affected': [{
          'database_specific': {
              'source': 'https://github.com/google/oss-fuzz-vulns/'
                        'blob/main/vulns/mruby/OSV-2020-744.yaml'
          },
          'ecosystem_specific': {
              'severity': 'HIGH'
          },
          'package': {
              'ecosystem': 'OSS-Fuzz',
              'name': 'mruby',
              'purl': 'pkg:generic/mruby'
          },
          'ranges': [{
              'events': [{
                  'introduced': '9cdf439db52b66447b4e37c61179d54fad6c8f33'
              }, {
                  'fixed': '97319697c8f9f6ff27b32589947e1918e3015503'
              }],
              'repo': 'https://github.com/mruby/mruby',
              'type': 'GIT'
          }],
          'versions': ['2.1.2', '2.1.2-rc', '2.1.2-rc2']
      }],
      'details': 'OSS-Fuzz report: '
                 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801\n'
                 '\n'
                 '```\n'
                 'Crash type: Heap-double-free\n'
                 'Crash state:\n'
                 'mrb_default_allocf\n'
                 'mrb_free\n'
                 'obj_free\n```\n',
      'id': 'OSV-2020-744',
      'references': [{
          'type': 'REPORT',
          'url': 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801',
      }],
      'summary': 'Heap-double-free in mrb_default_allocf',
  }

  def _get(self, vuln_id):
    """Get a vulnerability."""
    response = requests.get(_api() + '/v1/vulns/' + vuln_id)
    return response.json()

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def assert_vuln_equal(self, expected, actual):
    """Assert that the vulnerability is equal."""
    self.remove_modified(expected)
    self.remove_modified(actual)
    self.assertDictEqual(expected, actual)

  def assert_results_equal(self, expected, actual):
    """Assert that results are equal.

    Args:
      expected: dictionary representation of the expected vulnerability.
      actual: dictionary representation of the actual vulnerability.
    """
    # Single query results.
    for vuln in expected.get('vulns', []):
      self.remove_modified(vuln)

    for vuln in actual.get('vulns', []):
      self.remove_modified(vuln)

    # Batch query results.
    for batch_result in actual.get('results', []):
      for vuln in batch_result.get('vulns', {}):
        # Ensure that batch queries include the timestamp.
        self.remove_modified(vuln, check_exists=True)

    self.assertDictEqual(expected, actual)

  def remove_modified(self, vuln, check_exists=False):
    """Remove lastModified for comparison."""
    if 'modified' in vuln:
      del vuln['modified']
    elif check_exists:
      raise ValueError('Missing modified timestamp')

  def test_get(self):
    """Test getting a vulnerability."""
    response = requests.get(_api() + '/v1/vulns/OSV-2020-744')
    self.assert_vuln_equal(self._VULN_744, response.json())

  def test_get_with_multiple(self):
    """Test getting a vulnerability with multiple packages."""
    go_2020_0015 = self._get('GO-2020-0015')
    response = requests.get(_api() + '/v1/vulns/GO-2020-0015')
    self.assert_vuln_equal(go_2020_0015, response.json())

  def test_query_commit(self):
    """Test querying by commit."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'commit': '233cb49903fa17637bd51f4a16b4ca61e0750f24',
        }))
    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json())

  def test_query_version(self):
    """Test querying by version."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '2.1.2rc',
            'package': {
                'name': 'mruby',
                'ecosystem': 'OSS-Fuzz',
            }
        }))
    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '2.1.2-rc',
            'package': {
                'name': 'mruby',
            }
        }))
    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json())

  def test_query_debian(self):
    """Test querying Debian with sub ecosystem versions"""
    dsa_2665_1 = self._get('DSA-710-1')

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian',
            }
        }))
    self.assert_results_equal({'vulns': [dsa_2665_1]}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:3.0',
            }
        }))
    self.assert_results_equal({'vulns': [dsa_2665_1]}, response.json())

    # The vulnerbility does not exist in 4.0 release, so this should return
    # with nothing
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:4.0',
            }
        }))
    self.assert_results_equal({}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:9',
            }
        }))
    self.assert_results_equal({}, response.json())

  def test_query_semver(self):
    """Test query by SemVer."""
    go_2020_0004 = self._get('GO-2020-0004')
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-2017a',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
                'ecosystem': 'Go',
            }
        }))
    self.assert_results_equal({'vulns': [go_2020_0004]}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-2017a',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
            }
        }))
    self.assert_results_equal({'vulns': [go_2020_0004]}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-20160722212129-ac0cc4484ad4',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
                'ecosystem': 'Go',
            }
        }))
    self.assert_results_equal({'vulns': [go_2020_0004]}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-20200131131040-063a3fb69896',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
                'ecosystem': 'Go',
            }
        }))
    self.assert_results_equal({}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
                'ecosystem': 'Go',
            }
        }))
    self.assert_results_equal({}, response.json())

  def test_query_semver_multiple_package(self):
    """Test query by SemVer (with multiple packages)."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '2.4.0',
            'package': {
                'name': 'gopkg.in/yaml.v2',
                'ecosystem': 'Go',
            }
        }))

    self.assert_results_equal({}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '2.4.0',
            'package': {
                'name': 'github.com/go-yaml/yaml',
                'ecosystem': 'Go',
            }
        }))

    response_json = response.json()
    self.assertEqual(2, len(response_json['vulns']))
    self.assertCountEqual(['GO-2021-0061', 'GO-2020-0036'],
                          [vuln['id'] for vuln in response_json['vulns']])

  def test_query_purl(self):
    """Test querying by PURL."""
    expected = [
        self._get('GHSA-qc84-gqf4-9926'),
        self._get('RUSTSEC-2022-0041')
    ]

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.8.6',
            'package': {
                'purl': 'pkg:cargo/crossbeam-utils',
            }
        }))

    self.assert_results_equal({'vulns': expected}, response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps(
            {'package': {
                'purl': 'pkg:cargo/crossbeam-utils@0.8.6',
            }}))

    self.assert_results_equal({'vulns': expected}, response.json())

    expected_deb = [self._get('DSA-4921-1')]

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps(
            {'package': {
                'purl': 'pkg:deb/debian/nginx@1.14.2-2+deb10u3',
            }}))

    self.assert_results_equal({'vulns': expected_deb}, response.json())

    # Source arch should return the same as above
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'package': {
                'purl': 'pkg:deb/debian/nginx@1.14.2-2+deb10u3?arch=source',
            }
        }))

    self.assert_results_equal({'vulns': expected_deb}, response.json())

    # A non source arch should return nothing, as we don't index them
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'package': {
                'purl': 'pkg:deb/debian/nginx@1.14.2-2+deb10u3?arch=x64',
            }
        }))

    self.assert_results_equal({}, response.json())

    # A non arch qualifier should be ignored
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'package': {
                'purl': ('pkg:deb/debian/nginx@1.14.2-2+deb10u3?'
                         'randomqualifier=1234'),
            }
        }))

    self.assert_results_equal({'vulns': expected_deb}, response.json())

  def test_query_batch(self):
    """Test batch query."""
    response = requests.post(
        _api() + '/v1/querybatch',
        data=json.dumps({
            'queries': [{
                'version': '0.8.6',
                'package': {
                    'purl': 'pkg:cargo/crossbeam-utils',
                }
            }, {
                'version': '2.4.0',
                'package': {
                    'name': 'gopkg.in/yaml.v2',
                    'ecosystem': 'Go',
                }
            }, {
                'commit': '233cb49903fa17637bd51f4a16b4ca61e0750f24',
            }],
        }))

    self.assert_results_equal(
        {
            'results': [
                {
                    'vulns': [{
                        'id': 'GHSA-qc84-gqf4-9926',
                    }, {
                        'id': 'RUSTSEC-2022-0041',
                    }]
                },
                {},
                {
                    'vulns': [{
                        'id': 'OSV-2020-744',
                    }]
                },
            ]
        }, response.json())

  def test_query_package(self):
    """Test query by package."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'package': {
                'ecosystem': 'Maven',
                'name': 'org.apache.tomcat:tomcat',
            }
        }))

    result = response.json()
    vulns_first = set(v['id'] for v in result['vulns'])
    self.assertIn('next_page_token', result)

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'package': {
                'ecosystem': 'Maven',
                'name': 'org.apache.tomcat:tomcat',
            },
            'page_token': result['next_page_token'],
        }))

    result = response.json()
    vulns_second = set(v['id'] for v in result['vulns'])

    self.assertEqual(set(), vulns_first.intersection(vulns_second))

  def test_query_package_purl(self):
    """Test query by package (purl)."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps(
            {'package': {
                'purl': 'pkg:maven/org.apache.tomcat/tomcat',
            }}))
    result = response.json()
    vulns_first = set(v['id'] for v in result['vulns'])
    self.assertIn('next_page_token', result)

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'package': {
                'purl': 'pkg:maven/org.apache.tomcat/tomcat',
            },
            'page_token': result['next_page_token'],
        }))

    result = response.json()
    vulns_second = set(v['id'] for v in result['vulns'])

    self.assertEqual(set(), vulns_first.intersection(vulns_second))


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
