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

import copy
import functools
import json
import itertools
import os
import sys
import subprocess
import time
import unittest

import requests

import test_server
from osv import tests

_PORT = 8080
_TIMEOUT = 10  # Timeout for HTTP(S) requests
_LONG_TESTS = os.getenv('LONG_TESTS')
_TEST_DATA_DIR = 'fixtures'
_BASE_QUERY = '/v1/query'


def _api():
  if os.getenv('CLOUDBUILD'):
    host = test_server.get_cloudbuild_esp_host()
  else:
    host = 'localhost'

  return f'http://{host}:{_PORT}'


class IntegrationTests(unittest.TestCase,
                       tests.ExpectationTest(_TEST_DATA_DIR)):
  """Server integration tests."""
  _CVE_2024_2002 = {
      'id':
          'CVE-2024-2002',
      'details':
          'A double-free vulnerability was found in libdwarf. In a multiply-corrupted DWARF object, libdwarf may try to dealloc(free) an allocation twice, potentially causing unpredictable and various results.',  #pylint: disable=line-too-long
      'modified':
          '2025-04-10T03:36:25.951623Z',
      'published':
          '2024-03-18T13:15:07Z',
      'related': ['UBUNTU-CVE-2024-2002'],
      'references': [
          {
              'type':
                  'ARTICLE',
              'url':
                  'https://lists.fedoraproject.org/archives/list/package-announce@lists.fedoraproject.org/message/ZGPVLSPIXR32J6FOAFTTIMYTUUXJICGW/'  #pylint: disable=line-too-long
          },
          {
              'type': 'REPORT',
              'url': 'https://bugzilla.redhat.com/show_bug.cgi?id=2267700'
          },
          {
              'type': 'WEB',
              'url': 'https://access.redhat.com/security/cve/CVE-2024-2002'
          },
          {
              'type':
                  'WEB',
              'url':
                  'https://github.com/davea42/libdwarf-code/blob/main/bugxml/data.txt'  #pylint: disable=line-too-long
          },
          {
              'type': 'ADVISORY',
              'url': 'https://security-tracker.debian.org/tracker/CVE-2024-2002'
          }
      ],
      'affected': [
          {
              'package': {
                  'name': 'dwarfutils',
                  'ecosystem': 'Debian:11',
                  'purl': 'pkg:deb/debian/dwarfutils?arch=source'
              },
              'ranges': [{
                  'type': 'ECOSYSTEM',
                  'events': [{
                      'introduced': '0'
                  }]
              }],
              'versions': [
                  '1:0.11.1-1', '1:0.11.1-1~exp1', '1:0.11.1-1~exp2',
                  '20201201-1', '20210528-1'
              ],
              'ecosystem_specific': {
                  'urgency': 'not yet assigned'
              },
              'database_specific': {
                  'source':
                      'https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2024-2002.json'  #pylint: disable=line-too-long
              }
          },
          {
              'package': {
                  'name': 'dwarfutils',
                  'ecosystem': 'Debian:12',
                  'purl': 'pkg:deb/debian/dwarfutils?arch=source'
              },
              'ranges': [{
                  'type': 'ECOSYSTEM',
                  'events': [{
                      'introduced': '0'
                  }]
              }],
              'versions': [
                  '1:0.11.1-1', '1:0.11.1-1~exp1', '1:0.11.1-1~exp2',
                  '20210528-1'
              ],
              'ecosystem_specific': {
                  'urgency': 'not yet assigned'
              },
              'database_specific': {
                  'source':
                      'https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2024-2002.json'  #pylint: disable=line-too-long
              }
          },
          {
              'package': {
                  'name': 'dwarfutils',
                  'ecosystem': 'Debian:13',
                  'purl': 'pkg:deb/debian/dwarfutils?arch=source'
              },
              'ranges': [{
                  'type': 'ECOSYSTEM',
                  'events': [{
                      'introduced': '0'
                  }, {
                      'fixed': '1:0.11.1-1'
                  }]
              }],
              'versions': ['1:0.11.1-1~exp1', '1:0.11.1-1~exp2', '20210528-1'],
              'ecosystem_specific': {
                  'urgency': 'not yet assigned'
              },
              'database_specific': {
                  'source':
                      'https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2024-2002.json'  #pylint: disable=line-too-long
              }
          },
          {
              'ranges': [{
                  'type':
                      'GIT',
                  'repo':
                      'https://github.com/davea42/libdwarf-code',
                  'events': [{
                      'introduced': '0'
                  }, {
                      'fixed': '5e43a5ab73cb00c8a46660b361366a8c9c3c93c9'
                  }]
              }],
              'versions': [
                  '20110113', '20110605', '20110607', '20110612', '20110908',
                  '20111009', '20111030', '20111214', '20120410', '20121127',
                  '20121130', '20130125', '20130126', '20130207', '20130729',
                  '20130729-b', '20140131', '20140208', '20140413', '20140519',
                  '20140805', '20150112', '20150115', '20150310', '20150507',
                  '20150913', '20150915', '20151114', '20160116', '20160507',
                  '20160613', '20160923', '20160929', '20161001', '20161021',
                  '20161124', '20170416', '20170709', '20180129', '20180527',
                  '20180723', '20180724', '20180809', '20181024', '20190104',
                  '20190110', '20190505', '20190529', '20191002', '20191104',
                  '20200114', '20200703', '20200719', '20200825', '20201020',
                  '20201201', '20210305', '20210528', 'libdwarf-0.1.1',
                  'libdwarf-0.2.0', 'libdwarf-0.3.0', 'libdwarf-0.3.1',
                  'libdwarf-0.3.2', 'libdwarf-0.3.3', 'libdwarf-0.3.4',
                  'libdwarf-0.4.0', 'libdwarf-0.4.1', 'libdwarf-0.4.2',
                  'libdwarf-0.5.0', 'libdwarf-0.6.0', 'libdwarf-0.7.0',
                  'libdwarf-0.8.0-fixedtag', 'libdwarf-0.9.0', 'libdwarf-0.9.1',
                  'v0.3.4', 'v0.4.0', 'v0.4.1', 'v0.4.2', 'v0.5.0', 'v0.6.0',
                  'v0.7.0', 'v0.8.0', 'v0.8.0-fixedtag', 'v0.9.0', 'v0.9.1'
              ],
              'database_specific': {
                  'source':
                      'https://storage.googleapis.com/cve-osv-conversion/osv-output/CVE-2024-2002.json'  #pylint: disable=line-too-long
              }
          }
      ],
      'schema_version':
          '1.6.0'
  }
  _VULN_890 = {
      'id':
          'OSV-2023-890',
      'summary':
          'Heap-use-after-free in dwarf_dealloc',
      'details':
          'OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=62547\n\n```\nCrash type: Heap-use-after-free READ 2\nCrash state:\ndwarf_dealloc\n_dwarf_fde_destructor\ntdestroy_free_node\n```\n',  #pylint: disable=line-too-long
      'modified':
          '2023-09-21T14:01:03.576815Z',
      'published':
          '2023-09-21T14:01:03.576514Z',
      'references': [{
          'type': 'REPORT',
          'url': 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=62547'
      }],
      'affected': [{
          'package': {
              'name': 'libdwarf',
              'ecosystem': 'OSS-Fuzz',
              'purl': 'pkg:generic/libdwarf'
          },
          'ranges': [{
              'type':
                  'GIT',
              'repo':
                  'https://github.com/davea42/libdwarf-code',
              'events': [{
                  'introduced': 'b55ce0185528bf0a99e375cf8f3c84b76b6881a3'
              }, {
                  'fixed': 'cd741379bd0203a0875b413542d5f982606ae637'
              }]
          }],
          'versions': [
              'libdwarf-0.7.0', 'libdwarf-0.8.0-fixedtag', 'v0.7.0',
              'v0.8.0-fixedtag'
          ],
          'ecosystem_specific': {
              'severity': 'HIGH'
          },
          'database_specific': {
              'source':
                  'https://github.com/google/oss-fuzz-vulns/blob/main/vulns/libdwarf/OSV-2023-890.yaml'  #pylint: disable=line-too-long
          }
      }],
      'schema_version':
          '1.6.0'
  }

  _VULN_744 = {
      'published': '2020-07-04T00:00:01.948828Z',
      'schema_version': '1.6.0',
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
    response = requests.get(_api() + '/v1/vulns/' + vuln_id, timeout=_TIMEOUT)
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
    response = requests.get(_api() + '/v1/vulns/OSV-2020-744', timeout=_TIMEOUT)
    self.assert_vuln_equal(self._VULN_744, response.json())

  def test_get_with_multiple(self):
    """Test getting a vulnerability with multiple packages."""
    go_2020_0015 = self._get('GO-2020-0015')
    response = requests.get(_api() + '/v1/vulns/GO-2020-0015', timeout=_TIMEOUT)
    self.assert_vuln_equal(go_2020_0015, response.json())

  def test_query_commit(self):
    """Test querying by commit."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'commit': '60e572dbf7b4ded66b488f54773f66aaf6184321',
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': [self._CVE_2024_2002, self._VULN_890]},
                              response.json())

  def test_query_version(self):
    """Test querying by version."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.1.2-rc',
            'package': {
                'name': 'mruby',
                'ecosystem': 'OSS-Fuzz',
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json())

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.1.2-rc',
            'package': {
                'name': 'mruby',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json())
    # self.assertEqual(
    #   response.text,
    #   '{"code":3,"message":"Ecosystem not specified"}')

  def test_query_debian(self):
    """Test querying Debian with sub ecosystem versions"""
    dsa_2665_1 = self._get('DSA-710-1')

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian',
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': [dsa_2665_1]}, response.json())

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:3.0',
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': [dsa_2665_1]}, response.json())

    # The vulnerbility does not exist in 4.0 release, so this should return
    # with nothing
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:4.0',
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({}, response.json())

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:9',
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({}, response.json())

  def test_query_semver(self):
    """Test queries by SemVer."""

    package = 'github.com/gin-gonic/gin'
    ecosystem = 'Go'
    go_2020_0001 = self._get('GO-2020-0001')
    go_2021_0052 = self._get('GO-2021-0052')
    ghsa_6vm3_jj99_7229 = self._get('GHSA-6vm3-jj99-7229')
    ghsa_869c_j7wc_8jqv = self._get('GHSA-869c-j7wc-8jqv')
    ghsa_h395_qcrw_5vmq = self._get('GHSA-h395-qcrw-5vmq')
    ghsa_3vp4_m3rf_835h = self._get('GHSA-3vp4-m3rf-835h')

    expected_vulns = [
        ghsa_6vm3_jj99_7229,
        ghsa_869c_j7wc_8jqv,
        go_2020_0001,
        ghsa_h395_qcrw_5vmq,
        go_2021_0052,
        ghsa_3vp4_m3rf_835h,
    ]

    # Test that a SemVer (believed to be vulnerable) version and an ecosystem
    # returns expected vulnerabilities.
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.1.4',
            'package': {
                'name': package,
                'ecosystem': ecosystem,
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': expected_vulns}, response.json())

    # Test that a SemVer with a (believed to be vulnerable) version and no
    # ecosystem returns expected vulnerabilities to test the fallback logic to
    # try semver matching in the case that an ecosystem isn't specified.
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.1.4',
            'package': {
                'name': package,
                'ecosystem': 'Go'
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': expected_vulns}, response.json())

  def test_query_comparing_version(self):
    """Test queries by comparing versions."""

    package = 'linux-firmware'
    ecosystem = 'AlmaLinux:8'
    alsa_2023_7109 = self._get('ALSA-2023:7109')
    alsa_2024_3178 = self._get('ALSA-2024:3178')
    alsa_2024_4262 = self._get('ALSA-2024:4262')
    alsa_2024_7481 = self._get('ALSA-2024:7481')

    expected_vulns = [
        alsa_2023_7109,
        alsa_2024_3178,
        alsa_2024_4262,
        alsa_2024_7481,
    ]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '20230404-117.git2e92a49f.el8_8.alma.1',
            'package': {
                'name': package,
                'ecosystem': ecosystem,
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': expected_vulns}, response.json())

    # Tests empty response
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '99999999-117.git2e92a49f.el8_8.alma.1',
            'package': {
                'name': package,
                'ecosystem': ecosystem,
            }
        }),
        timeout=_TIMEOUT)
    self.assertEqual(0, len(response.json()))

  def test_malicious_package_matching(self):
    """"Test malicious package query"""
    # Test matching by affected ranges
    mal_2022_7426 = self._get('MAL-2022-7426')

    expected_vulns = [
        mal_2022_7426,
    ]

    package = 'pymocks'
    ecosystem = 'PyPI'

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '0.0.1',
            'package': {
                'name': package,
                'ecosystem': ecosystem,
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': expected_vulns}, response.json())

    # Test matching by affected versions
    mal_2024_4618 = self._get('MAL-2024-4618')

    expected_vulns = [
        mal_2024_4618,
    ]

    package = 'psbuiId'
    ecosystem = 'NuGet'

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.1.1-beta',
            'package': {
                'name': package,
                'ecosystem': ecosystem,
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({'vulns': expected_vulns}, response.json())

  def test_query_invalid_ecosystem(self):
    """Test a query with an invalid ecosystem fails validation."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.0',
            'package': {
                'name': 'a_package_name_of_no_consequence',
                'ecosystem': 'Bogus',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({
        'code': 3,
        'message': 'Invalid ecosystem.'
    }, response.json())

  def test_query_unknown_purl_invalid_semver(self):
    """Test an unknown purl query with an invalid semver"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl':
                    'pkg:golang/github.com/' +
                    'tianon/gosu@(devel)?package-id=656546dcfdff37ca',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({}, response.json())

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl':
                    'pkg:yeet/github.com/' +
                    'tianon/gosu@(devel)?package-id=656546dcfdff37ca',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({}, response.json())

  def test_query_semver_no_vulns(self):
    """Test queries by SemVer with no vulnerabilities."""
    package = 'github.com/justinas/nosurf'
    ecosystem = 'Go'

    # Test that a SemVer with a (believed to be non-vulnerable) version and an
    # ecosystem returns no vulnerabilities.
    # (This version does not exist)
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.2.1',
            'package': {
                'name': package,
                'ecosystem': ecosystem,
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal({}, response.json())

  def test_query_semver_multiple_package(self):
    """Test query by SemVer (with multiple packages)."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.4.0',
            'package': {
                'name': 'gopkg.in/yaml.v2',
                'ecosystem': 'Go',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({}, response.json())

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.4.0',
            'package': {
                'name': 'github.com/go-yaml/yaml',
                'ecosystem': 'Go',
            }
        }),
        timeout=_TIMEOUT)

    response_json = response.json()
    self.assertCountEqual(['GO-2021-0061', 'GO-2020-0036'],
                          [vuln['id'] for vuln in response_json['vulns']])

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '7.1.1',
            'package': {
                'name': 'ws',
                'ecosystem': 'npm',
            }
        }),
        timeout=_TIMEOUT)

    response_json = response.json()
    self.assertEqual(2, len(response_json['vulns']))
    self.assertCountEqual(['GHSA-6fc8-4gx4-v693', 'GHSA-3h5v-q93c-6h6q'],
                          [vuln['id'] for vuln in response_json['vulns']])

  def test_query_purl(self):
    """Test querying by PURL."""
    expected = [
        self._get('GHSA-qc84-gqf4-9926'),
        self._get('RUSTSEC-2022-0041')
    ]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '0.8.6',
            'package': {
                'purl': 'pkg:cargo/crossbeam-utils',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': expected}, response.json())

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'purl': 'pkg:cargo/crossbeam-utils@0.8.6',
            }}),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': expected}, response.json())

    another_expected = [self._get('GHSA-j8xg-fqg3-53r7')]
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:npm/word-wrap@1.2.2',
        }}),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': another_expected}, response.json())

    expected_deb = [
        self._get('CVE-2018-25047'),
        self._get('CVE-2023-28447'),
        self._get('CVE-2024-35226'),
        self._get('DSA-5830-1'),
    ]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'purl': 'pkg:deb/debian/smarty4@4.1.1-1',
            }}),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': expected_deb}, response.json())

    # Source arch should return the same as above
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl': 'pkg:deb/debian/smarty4@4.1.1-1?arch=source',
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': expected_deb}, response.json())

    # A non source arch should also return the same item
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'purl': 'pkg:deb/debian/smarty4@4.1.1-1?arch=x64',
            }}),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': expected_deb}, response.json())

    # A non arch qualifier should be ignored
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl': ('pkg:deb/debian/smarty4@4.1.1-1?'
                         'randomqualifier=1234'),
            }
        }),
        timeout=_TIMEOUT)

    self.assert_results_equal({'vulns': expected_deb}, response.json())

  def test_query_purl_with_version_trailing_zeroes(self):
    """Test purl with trailing zeroes in version."""
    expected = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:pypi/cryptography@3.1',
        }}),
        timeout=_TIMEOUT)

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:pypi/cryptography@3.1.0',
        }}),
        timeout=_TIMEOUT)

    self.assert_results_equal(expected.json(), response.json())

    expected = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:nuget/SkiaSharp@2.80.3',
        }}),
        timeout=_TIMEOUT)

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:nuget/SkiaSharp@2.80.3.0',
        }}),
        timeout=_TIMEOUT)

    self.assert_results_equal(expected.json(), response.json())

    expected = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:pypi/django@4.2',
        }}),
        timeout=_TIMEOUT)
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:pypi/django@4.2.0',
        }}),
        timeout=_TIMEOUT)

    self.assert_results_equal(expected.json(), response.json())

  def test_query_with_redundant_ecosystem(self):
    """Test purl with redundant ecosystem raises error"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            "package": {
                "ecosystem": "PyPI",
                "purl": "pkg:pypi/mlflow@0.4.0",
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal(
        {
            'code': 3,
            'message': 'ecosystem specified in a PURL query'
        }, response.json())

  def test_query_with_redundant_version(self):
    """Test purl with redundant version raises error"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            "version": "0.4.0",
            "package": {
                "purl": "pkg:pypi/mlflow@0.4.0",
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal(
        {
            'code': 3,
            'message': 'version specified in params and PURL query'
        }, response.json())

  def test_query_with_redundant_package_name(self):
    """Test purl with redundant name raises error"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {"package": {
                "name": "mlflow",
                "purl": "pkg:pypi/mlflow@0.4.0",
            }}),
        timeout=_TIMEOUT)
    self.assert_results_equal(
        {
            'code': 3,
            'message': 'name specified in a PURL query'
        }, response.json())

  def test_get_vuln_by_alias_not_in_db(self):
    """ Test search by ID for a vuln not in db, but alias is"""
    response = requests.get(
        _api() + '/v1/vulns/CVE-2024-40120', timeout=_TIMEOUT)
    self.assert_results_equal(
        {
            'code': 5,
            'message': 'Bug not found, but the following aliases were: '
                       'GHSA-q97m-8853-pq76'
        }, response.json())

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
        }),
        timeout=_TIMEOUT)

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
                        'id': 'CVE-2020-15866',
                    }, {
                        'id': 'CVE-2020-36401',
                    }, {
                        'id': 'CVE-2021-4110',
                    }, {
                        'id': 'CVE-2021-4188',
                    }, {
                        'id': 'CVE-2021-46020',
                    }, {
                        'id': 'CVE-2021-46023',
                    }, {
                        'id': 'CVE-2022-0080',
                    }, {
                        'id': 'CVE-2022-0240',
                    }, {
                        'id': 'CVE-2022-0326',
                    }, {
                        'id': 'CVE-2022-0481',
                    }, {
                        'id': 'CVE-2022-0525',
                    }, {
                        'id': 'CVE-2022-0570',
                    }, {
                        'id': 'CVE-2022-0614',
                    }, {
                        'id': 'CVE-2022-0623',
                    }, {
                        'id': 'CVE-2022-0630',
                    }, {
                        'id': 'CVE-2022-0631',
                    }, {
                        'id': 'CVE-2022-0632',
                    }, {
                        'id': 'CVE-2022-0717',
                    }, {
                        'id': 'CVE-2022-0890',
                    }, {
                        'id': 'CVE-2022-1071',
                    }, {
                        'id': 'CVE-2022-1106',
                    }, {
                        'id': 'CVE-2022-1201',
                    }, {
                        'id': 'CVE-2022-1212',
                    }, {
                        'id': 'CVE-2022-1276',
                    }, {
                        'id': 'CVE-2022-1286',
                    }, {
                        'id': 'CVE-2022-1427',
                    }, {
                        'id': 'CVE-2022-1934',
                    }, {
                        'id': 'OSV-2020-744',
                    }]
                },
            ]
        }, response.json())

  @unittest.skipIf(
      os.getenv('LOW_MAX_THRESH', '0') != '1', "Run this test locally with " +
      "MAX_VULN_LISTED_PRE_EXCEEDED at a lower value (around 10)")
  def test_query_pagination(self):
    """Test query by package with pagination."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'ecosystem': 'PyPI',
                'name': 'tensorflow',
            }}),
        timeout=_TIMEOUT)

    result = response.json()
    vulns_first = set(v['id'] for v in result['vulns'])
    self.assertIn('next_page_token', result)

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'ecosystem': 'PyPI',
                'name': 'tensorflow',
            },
            'page_token': result['next_page_token'],
        }),
        timeout=_TIMEOUT)

    result = response.json()
    vulns_second = set(v['id'] for v in result['vulns'])

    self.assertEqual(set(), vulns_first.intersection(vulns_second))

  @unittest.skipIf(
      os.getenv('LOW_MAX_THRESH', '0') != '1', "Run this test locally with " +
      "MAX_VULN_LISTED_PRE_EXCEEDED at a lower value (around 10)")
  def test_query_pagination_no_ecosystem(self):
    """Test query with pagination but no ecosystem."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'name': 'django',
            },
            # Test with a version that is ambiguous whether it
            # belongs to semver or generic version
            'version': '5.0.1',
        }),
        timeout=_TIMEOUT)

    result = response.json()
    vulns_first = set(v['id'] for v in result['vulns'])
    self.assertIn('next_page_token', result)
    self.assertTrue(str.startswith(result['next_page_token'], '2:'))

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'name': 'django',
            },
            'version': '5.0.1',
            'page_token': result['next_page_token'],
        }),
        timeout=_TIMEOUT)

    result = response.json()
    vulns_second = set(v['id'] for v in result['vulns'])

    self.assertIn('next_page_token', result)
    # There is not enough django vulns to simultaneously test multiple pages,
    # and pass the other tests
    # self.assertTrue(str.startswith(result['next_page_token'], '1:'))
    self.assertEqual(set(), vulns_first.intersection(vulns_second))

  @unittest.skipIf(
      os.getenv('LOW_MAX_THRESH', '0') != '1', "Run this test locally with " +
      "MAX_VULN_LISTED_PRE_EXCEEDED at a lower value (around 10)")
  def test_query_package_purl_paging(self):
    """Test query by package (purl)."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:pypi/tensorflow',
        }}),
        timeout=_TIMEOUT)
    result = response.json()
    vulns_first = set(v['id'] for v in result['vulns'])
    self.assertIn('next_page_token', result)

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl': 'pkg:pypi/tensorflow',
            },
            'page_token': result['next_page_token'],
        }),
        timeout=_TIMEOUT)

    result = response.json()
    vulns_second = set(v['id'] for v in result['vulns'])

    self.assertEqual(set(), vulns_first.intersection(vulns_second))

  @unittest.skipUnless(
      _LONG_TESTS, "Takes around 45 seconds running locally," +
      "enable when making a big change")
  def test_all_possible_queries(self):
    """Test all combinations of valid and invalid queries"""
    semver_package = {'package': {'purl': 'pkg:cargo/crossbeam-utils'}}

    semver_package_with_version = {
        'package': {
            'purl': 'pkg:cargo/crossbeam-utils@0.8.5'
        }
    }

    nonsemver_package = {'package': {'purl': 'pkg:pypi/numpy'}}

    nonsemver_package_with_version = {
        'package': {
            'purl': 'pkg:pypi/numpy@8.24.0'
        }
    }

    pkg_ecosystem = [{'package': {'ecosystem': 'crates.io'}}, {}]

    pkg_name = [{
        'package': {
            'name': 'crossbeam-utils'
        }
    }, {
        'package': {
            'name': 'numpy'
        }
    }, {}]

    pkg_version = [{'version': '0.8.5'}, {}]

    commit = [{'commit': 'd374094d8c49b6b7d288f307e11217ec5a502391'}, {}]

    purl_fields = [
        semver_package, semver_package_with_version, nonsemver_package,
        nonsemver_package_with_version, {}
    ]

    product = itertools.product(purl_fields, commit, pkg_version, pkg_name,
                                pkg_ecosystem)

    # itertools.product will produce duplicates, use set over the json to de-dup
    combined_product = set()
    for elem in product:
      # Deep copy elem required since merge merges
      # in-place to the first argument
      elem = copy.deepcopy(elem)
      functools.reduce(merge, elem)
      combined_product.add(json.dumps(elem[0], sort_keys=True))

    self.assertEqual(len(combined_product), 120)

    actual_lines = []
    for query in sorted(list(combined_product)):
      response = requests.post(
          _api() + _BASE_QUERY, data=query, timeout=_TIMEOUT)

      # No possible queries should cause a server error
      self.assertLess(response.status_code, 500)
      actual_lines.append(str(response.status_code) + ':' + query + '\n')

    self.expect_lines_equal('api_query_response', actual_lines)


# From: https://stackoverflow.com/questions/7204805/how-to-merge-dictionaries-of-dictionaries  # pylint: disable=line-too-long
def merge(a: dict, b: dict, path=None):
  """Merge two nested dictionaries"""
  if path is None:
    path = []

  for key in b:
    if key in a:
      if isinstance(a[key], dict) and isinstance(b[key], dict):
        merge(a[key], b[key], path + [str(key)])
      elif a[key] != b[key]:
        # pylint: disable=broad-exception-raised
        raise Exception('Conflict at ' + '.'.join(path + [str(key)]))
    else:
      a[key] = b[key]
  return a


def print_logs(filename):
  """Print logs."""
  if not os.path.exists(filename):
    return

  print(filename + ':')
  with open(filename) as f:
    print(f.read())


if __name__ == '__main__':
  if len(sys.argv) < 2:
    print(
        f'Usage: {sys.argv[0]} path/to/credential.json [...optional specific tests]'
    )
    sys.exit(1)

  subprocess.run(
      ['docker', 'pull', 'gcr.io/endpoints-release/endpoints-runtime:2'],
      check=True)

  credential_path = sys.argv.pop(1)
  server = test_server.start(credential_path, port=_PORT)
  time.sleep(10)

  try:
    unittest.main(argv=sys.argv)
  finally:
    server.stop()
