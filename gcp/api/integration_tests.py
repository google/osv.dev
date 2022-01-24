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
                 'Crash type: Heap-double-free\n'
                 'Crash state:\n'
                 'mrb_default_allocf\n'
                 'mrb_free\n'
                 'obj_free\n',
      'id': 'OSV-2020-744',
      'references': [{
          'type': 'REPORT',
          'url': 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801',
      }],
      'summary': 'Heap-double-free in mrb_default_allocf',
  }

  _VULN_2258 = {
      'published': '2020-12-11T00:00:45.856Z',
      'schema_version': '1.2.0',
      'details': 'INVALID',
      'id': 'OSV-2020-2258',
      'references': [{
          'type': 'REPORT',
          'url': 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=28505',
      }],
      'summary': 'Heap-buffer-overflow in grk::t1_part1::T1Part1::decompress',
  }

  _VULN_GO_2020_0004 = {
      'schema_version':
          '1.2.0',
      'id':
          'GO-2020-0004',
      'affected': [{
          'database_specific': {
              'source': 'https://storage.googleapis.com/go-vulndb/'
                        'byID/GO-2020-0004.json',
              'url': 'https://go.googlesource.com/vulndb/+/refs/heads/'
                     'master/reports/GO-2020-0004.yaml'
          },
          'ecosystem_specific': {
              'symbols': [
                  'Auth.ServerHTTP', 'Auth.ListenAndServeTLS',
                  'Auth.ListenAndServe'
              ],
          },
          'package': {
              'ecosystem': 'Go',
              'name': 'github.com/nanobox-io/golang-nanoauth',
              'purl': 'pkg:golang/github.com/nanobox-io/golang-nanoauth'
          },
          'ranges': [{
              'events': [{
                  'introduced': '0.0.0-20160722212129-ac0cc4484ad4'
              }, {
                  'fixed': '0.0.0-20200131131040-063a3fb69896'
              }],
              'type': 'SEMVER'
          }]
      }],
      'details':
          'If any of the `ListenAndServe` functions are called with an '
          'empty token,\ntoken authentication is disabled globally for '
          'all listeners.\n\nAlso, a minor timing side channel was '
          'present allowing attackers with\nvery low latency and able '
          'to make a lot of requests to potentially\nrecover the '
          'token.\n',
      'published':
          '2021-04-14T12:00:00Z',
      'references': [{
          'type': 'FIX',
          'url': 'https://github.com/nanobox-io/golang-nanoauth/pull/5'
      }, {
          'type': 'FIX',
          'url': 'https://github.com/nanobox-io/golang-nanoauth/commit/'
                 '063a3fb69896acf985759f0fe3851f15973993f3'
      }],
  }

  _VULN_GO_2020_0015 = {
      'schema_version':
          '1.2.0',
      'affected': [{
          'database_specific': {
              'source': 'https://storage.googleapis.com/go-vulndb/byID/'
                        'GO-2020-0015.json',
              'url': 'https://go.googlesource.com/vulndb/+/refs/heads/master/'
                     'reports/GO-2020-0015.yaml'
          },
          'ecosystem_specific': {
              'symbols': ['utf16Decoder.Transform']
          },
          'package': {
              'ecosystem': 'Go',
              'name': 'golang.org/x/text/encoding/unicode',
              'purl': 'pkg:golang/golang.org/x/text/encoding/unicode',
          },
          'ranges': [{
              'events': [{
                  'introduced': '0'
              }, {
                  'fixed': '0.3.3'
              }],
              'type': 'SEMVER'
          }]
      }, {
          'database_specific': {
              'source': 'https://storage.googleapis.com/go-vulndb/byID/'
                        'GO-2020-0015.json',
              'url': 'https://go.googlesource.com/vulndb/+/refs/heads/master/'
                     'reports/GO-2020-0015.yaml'
          },
          'ecosystem_specific': {
              'symbols': ['Transform']
          },
          'package': {
              'ecosystem': 'Go',
              'name': 'golang.org/x/text/transform',
              'purl': 'pkg:golang/golang.org/x/text/transform'
          },
          'ranges': [{
              'events': [{
                  'introduced': '0'
              }, {
                  'fixed': '0.3.3'
              }],
              'type': 'SEMVER'
          }]
      }],
      'aliases': ['CVE-2020-14040'],
      'details':
          'An attacker could provide a single byte to a [`UTF16`] decoder '
          'instantiated with\n'
          '[`UseBOM`] or [`ExpectBOM`] to trigger an infinite loop if the '
          '[`String`] function on\n'
          'the [`Decoder`] is called, or the [`Decoder`] is passed to '
          '[`transform.String`].\n'
          'If used to parse user supplied input, this may be used as a '
          'denial of service\n'
          'vector.\n',
      'id':
          'GO-2020-0015',
      'published':
          '2021-04-14T12:00:00Z',
      'references': [{
          'type': 'FIX',
          'url': 'https://go-review.googlesource.com/c/text/+/238238'
      }, {
          'type': 'FIX',
          'url': 'https://github.com/golang/text/commit/'
                 '23ae387dee1f90d29a23c0e87ee0b46038fbed0e'
      }, {
          'type': 'WEB',
          'url': 'https://github.com/golang/go/issues/39491'
      }, {
          'type': 'WEB',
          'url': 'https://groups.google.com/g/golang-announce/c/bXVeAmGOqz0'
      }]
  }

  _VULN_RUSTSEC_2020_0105 = {
      'schema_version':
          '1.2.0',
      'id':
          'RUSTSEC-2020-0105',
      'summary':
          'Update unsound DrainFilter and RString::retain',
      'details':
          'Affected versions of this crate contained code from the '
          'Rust standard library that contained soundness bugs '
          'rust-lang/rust#60977 (double drop) & rust-lang/rust#78498 '
          '(create invalid utf-8 string).\n\n'
          'The flaw was corrected in v0.9.1 by making a similar fix '
          'to the one made in the Rust standard library.',
      'aliases': ['CVE-2020-36212', 'CVE-2020-36213'],
      'published':
          '2020-12-21T12:00:00Z',
      'references': [{
          'type': 'PACKAGE',
          'url': 'https://crates.io/crates/abi_stable'
      }, {
          'type': 'ADVISORY',
          'url': 'https://rustsec.org/advisories/RUSTSEC-2020-0105.html'
      }, {
          'type': 'REPORT',
          'url': 'https://github.com/rodrimati1992/abi_stable_crates/issues/44'
      }],
      'affected': [{
          'package': {
              'name': 'abi_stable',
              'ecosystem': 'crates.io',
              'purl': 'pkg:cargo/abi_stable'
          },
          'ranges': [{
              'type': 'SEMVER',
              'events': [{
                  'introduced': '0.0.0-0'
              }, {
                  'fixed': '0.9.1'
              }]
          }],
          'ecosystem_specific': {
              'affects': {
                  'functions': [],
                  'arch': [],
                  'os': []
              }
          },
          'database_specific': {
              'informational': None,
              'cvss': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H',
              'categories': ['memory-corruption'],
              'source': 'https://github.com/rustsec/advisory-db/blob/'
                        'osv/crates/RUSTSEC-2020-0105.json'
          }
      }]
  }

  def setUp(self):
    self.maxDiff = None  # pylint: disable=invalid-name

  def assert_vuln_equal(self, expected, actual):
    """Assert that the vulnerability is equal."""
    self.remove_modified(actual)
    self.assertDictEqual(expected, actual)

  def assert_results_equal(self, expected, actual):
    for vuln in actual.get('vulns', []):
      self.remove_modified(vuln)

    self.assertDictEqual(expected, actual)

  def remove_modified(self, vuln):
    """Remove lastModified for comparison."""
    if 'modified' in vuln:
      del vuln['modified']

  def test_get(self):
    """Test getting a vulnerability."""
    response = requests.get(_api() + '/v1/vulns/OSV-2020-744')
    self.assert_vuln_equal(self._VULN_744, response.json())

  def test_get_with_multiple(self):
    """Test getting a vulnerability with multiple packages."""
    response = requests.get(_api() + '/v1/vulns/GO-2020-0015')
    self.assert_vuln_equal(self._VULN_GO_2020_0015, response.json())

  def test_get_invalid(self):
    """Test getting an invalid vulnerability."""
    response = requests.get(_api() + '/v1/vulns/OSV-2020-2258')
    self.assert_vuln_equal(self._VULN_2258, response.json())

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

  def test_query_semver(self):
    """Test query by SemVer."""
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-2017a',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
                'ecosystem': 'Go',
            }
        }))
    self.assert_results_equal({'vulns': [self._VULN_GO_2020_0004]},
                              response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-2017a',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
            }
        }))
    self.assert_results_equal({'vulns': [self._VULN_GO_2020_0004]},
                              response.json())

    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.0.0-20160722212129-ac0cc4484ad4',
            'package': {
                'name': 'github.com/nanobox-io/golang-nanoauth',
                'ecosystem': 'Go',
            }
        }))
    self.assert_results_equal({'vulns': [self._VULN_GO_2020_0004]},
                              response.json())

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
    response = requests.post(
        _api() + '/v1/query',
        data=json.dumps({
            'version': '0.9.0',
            'package': {
                'purl': 'pkg:cargo/abi_stable',
            }
        }))

    self.assert_results_equal({'vulns': [self._VULN_RUSTSEC_2020_0105]},
                              response.json())


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
