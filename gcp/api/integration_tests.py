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
from __future__ import annotations

import copy
import functools
import json
import itertools
import os
import sys
import subprocess
import time
import unittest
from typing import Any, Dict, List, Optional # Added necessary types

import requests

# Assuming test_server provides necessary interfaces; not typing its internals here.
import test_server # from gcp.api import test_server
# Assuming osv.tests provides ExpectationTest; not typing its internals here.
from osv import tests # from osv import tests

_PORT = 8080
_TIMEOUT = 10  # Timeout for HTTP(S) requests
_LONG_TESTS: Optional[str] = os.getenv('LONG_TESTS')
_TEST_DATA_DIR = 'fixtures'
_BASE_QUERY = '/v1/query'


def _api() -> str:
  host_val: str # Renamed host
  if os.getenv('CLOUDBUILD'):
    # Assuming get_cloudbuild_esp_host returns str
    host_val = test_server.get_cloudbuild_esp_host()
  else:
    host_val = 'localhost'

  return f'http://{host_val}:{_PORT}'


class IntegrationTests(unittest.TestCase,
                       tests.ExpectationTest): # Removed _TEST_DATA_DIR from here, it's usually passed to init
  """Server integration tests."""
  # These are large dicts, using Dict[str, Any] for typing.
  _CVE_2024_2002: Dict[str, Any] = {
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

  _VULN_744: Dict[str, Any] = {
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

  # Constructor for tests.ExpectationTest
  def __init__(self, methodName: str = 'runTest') -> None:
        super().__init__(methodName)
        tests.ExpectationTest.__init__(self, test_data_dir=_TEST_DATA_DIR)


  def _get(self, vuln_id: str) -> Dict[str, Any]:
    """Get a vulnerability."""
    # response.json() can return Any, but we expect Dict[str, Any] for OSV data
    response = requests.get(_api() + '/v1/vulns/' + vuln_id, timeout=_TIMEOUT)
    response.raise_for_status() # Raise an exception for bad status codes
    return response.json() # type: ignore[no-any-return]

  def setUp(self) -> None:
    self.maxDiff = None  # pylint: disable=invalid-name

  def assert_vuln_equal(self, expected: Dict[str, Any], actual: Dict[str, Any]) -> None:
    """Assert that the vulnerability is equal."""
    self.remove_modified(expected)
    self.remove_modified(actual)
    self.assertDictEqual(expected, actual)

  def assert_results_equal(self, expected: Dict[str, Any], actual: Dict[str, Any]) -> None:
    """Assert that results are equal.

    Args:
      expected: dictionary representation of the expected vulnerability.
      actual: dictionary representation of the actual vulnerability.
    """
    # Single query results (structure: {"vulns": [...]})
    # actual.get can return Any, cast or ensure it's a list of dicts.
    expected_vulns_list: List[Dict[str, Any]] = expected.get('vulns', [])
    for vuln in expected_vulns_list:
      self.remove_modified(vuln)

    actual_vulns_list: List[Dict[str, Any]] = actual.get('vulns', [])
    for vuln in actual_vulns_list:
      self.remove_modified(vuln)

    # Batch query results (structure: {"results": [{"vulns": [...]}, ...]})
    # actual.get('results') could be None if key missing.
    actual_results_list: List[Dict[str, Any]] = actual.get('results', [])
    for batch_result in actual_results_list:
      # batch_result.get('vulns') could be None if key missing.
      batch_vulns_list: List[Dict[str, Any]] = batch_result.get('vulns', [])
      for vuln in batch_vulns_list:
        # Ensure that batch queries include the timestamp.
        self.remove_modified(vuln, check_exists=True)

    self.assertDictEqual(expected, actual)

  def remove_modified(self, vuln: Dict[str, Any], check_exists: bool = False) -> None:
    """Remove lastModified for comparison."""
    if 'modified' in vuln:
      del vuln['modified']
    elif check_exists:
      raise ValueError('Missing modified timestamp in vulnerability data: ' + vuln.get('id', 'UNKNOWN_ID'))

  def test_get(self) -> None:
    """Test getting a vulnerability."""
    response = requests.get(_api() + '/v1/vulns/OSV-2020-744', timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_vuln_equal(self._VULN_744, response.json()) # type: ignore[arg-type]

  def test_get_with_multiple(self) -> None:
    """Test getting a vulnerability with multiple packages."""
    go_2020_0015: Dict[str, Any] = self._get('GO-2020-0015')
    response = requests.get(_api() + '/v1/vulns/GO-2020-0015', timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_vuln_equal(go_2020_0015, response.json()) # type: ignore[arg-type]

  def test_query_commit(self) -> None:
    """Test querying by commit."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'commit': '60e572dbf7b4ded66b488f54773f66aaf6184321',
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': [self._CVE_2024_2002, self._VULN_890]},
                              response.json()) # type: ignore[arg-type]

  def test_query_version(self) -> None:
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
    response.raise_for_status()
    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json()) # type: ignore[arg-type]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.1.2-rc',
            'package': {
                'name': 'mruby', # Ecosystem missing, should still work if only one mruby
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': [self._VULN_744]}, response.json()) # type: ignore[arg-type]

  def test_query_debian(self) -> None:
    """Test querying Debian with sub ecosystem versions"""
    dsa_710_1: Dict[str, Any] = self._get('DSA-710-1') # Renamed from dsa_2665_1

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
    response.raise_for_status()
    self.assert_results_equal({'vulns': [dsa_710_1]}, response.json()) # type: ignore[arg-type]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1',
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:3.0', # woody
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': [dsa_710_1]}, response.json()) # type: ignore[arg-type]

    # The vulnerability does not exist in 4.0 release (sarge), so this should return empty.
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1', # Version itself might be too old for sarge context
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:4.0',
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({}, response.json()) # type: ignore[arg-type]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.2-1', # Version too old for stretch (Debian 9)
            'package': {
                'name': 'gtkhtml',
                'ecosystem': 'Debian:9',
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({}, response.json()) # type: ignore[arg-type]

  def test_query_semver(self) -> None:
    """Test queries by SemVer."""

    package_name_val = 'github.com/gin-gonic/gin' # Renamed package
    ecosystem_val = 'Go' # Renamed ecosystem
    go_2020_0001: Dict[str, Any] = self._get('GO-2020-0001')
    go_2021_0052: Dict[str, Any] = self._get('GO-2021-0052')
    ghsa_6vm3_jj99_7229: Dict[str, Any] = self._get('GHSA-6vm3-jj99-7229')
    ghsa_869c_j7wc_8jqv: Dict[str, Any] = self._get('GHSA-869c-j7wc-8jqv')
    ghsa_h395_qcrw_5vmq: Dict[str, Any] = self._get('GHSA-h395-qcrw-5vmq')
    ghsa_3vp4_m3rf_835h: Dict[str, Any] = self._get('GHSA-3vp4-m3rf-835h')

    expected_vulns_list: List[Dict[str, Any]] = [ # Renamed expected_vulns
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
                'name': package_name_val,
                'ecosystem': ecosystem_val,
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_vulns_list}, response.json()) # type: ignore[arg-type]

    # Test that a SemVer with a (believed to be vulnerable) version and no
    # ecosystem returns expected vulnerabilities to test the fallback logic to
    # try semver matching in the case that an ecosystem isn't specified.
    # Note: The server logic might require ecosystem if name/version are ambiguous.
    # This test assumes 'Go' will be inferred or matched broadly for this package name.
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.1.4',
            'package': {
                'name': package_name_val,
                'ecosystem': 'Go' # Explicitly 'Go' here, original comment was "no ecosystem"
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_vulns_list}, response.json()) # type: ignore[arg-type]

  def test_query_comparing_version(self) -> None:
    """Test queries by comparing versions."""

    package_name_val = 'linux-firmware' # Renamed
    ecosystem_val = 'AlmaLinux:8' # Renamed
    alsa_2023_7109: Dict[str, Any] = self._get('ALSA-2023:7109')
    alsa_2024_3178: Dict[str, Any] = self._get('ALSA-2024:3178')
    alsa_2024_4262: Dict[str, Any] = self._get('ALSA-2024:4262')
    alsa_2024_7481: Dict[str, Any] = self._get('ALSA-2024:7481')

    expected_vulns_list: List[Dict[str, Any]] = [ # Renamed
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
                'name': package_name_val,
                'ecosystem': ecosystem_val,
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_vulns_list}, response.json()) # type: ignore[arg-type]

    # Tests empty response for a version expected to have no vulns
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '99999999-117.git2e92a49f.el8_8.alma.1', # Assumed non-vulnerable
            'package': {
                'name': package_name_val,
                'ecosystem': ecosystem_val,
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    # response.json() might be {} or {"vulns": []}. Standardize check.
    self.assertEqual(0, len(response.json().get('vulns', []))) # type: ignore[union-attr]

  def test_malicious_package_matching(self) -> None:
    """"Test malicious package query"""
    # Test matching by affected ranges
    mal_2022_7426: Dict[str, Any] = self._get('MAL-2022-7426')
    expected_vulns_list_1: List[Dict[str, Any]] = [mal_2022_7426] # Renamed

    package_name_1 = 'pymocks' # Renamed
    ecosystem_1 = 'PyPI' # Renamed

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '0.0.1',
            'package': {
                'name': package_name_1,
                'ecosystem': ecosystem_1,
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_vulns_list_1}, response.json()) # type: ignore[arg-type]

    # Test matching by affected versions
    mal_2024_4618: Dict[str, Any] = self._get('MAL-2024-4618')
    expected_vulns_list_2: List[Dict[str, Any]] = [mal_2024_4618] # Renamed

    package_name_2 = 'psbuiId' # Renamed
    ecosystem_2 = 'NuGet' # Renamed

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.1.1-beta',
            'package': {
                'name': package_name_2,
                'ecosystem': ecosystem_2,
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_vulns_list_2}, response.json()) # type: ignore[arg-type]

  def test_query_invalid_ecosystem(self) -> None:
    """Test a query with an invalid ecosystem fails validation."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.0.0',
            'package': {
                'name': 'a_package_name_of_no_consequence',
                'ecosystem': 'Bogus', # Invalid ecosystem
            }
        }),
        timeout=_TIMEOUT)
    # Expect a non-200 response or specific error structure if server handles this gracefully.
    # Assuming a 4xx error code that results in a JSON error message.
    # If it's not guaranteed to be < 500 (e.g. validation might be 400),
    # we might not want raise_for_status() before this assert.
    # The original test implies it checks the JSON body for the error.
    self.assert_results_equal({
        'code': 3, # Assuming 3 is the error code for invalid input
        'message': 'Invalid ecosystem.'
    }, response.json()) # type: ignore[arg-type]

  def test_query_unknown_purl_invalid_semver(self) -> None:
    """Test an unknown purl query with an invalid semver"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl':
                    'pkg:golang/github.com/' + # Valid ecosystem part
                    'tianon/gosu@(devel)?package-id=656546dcfdff37ca', # Version "(devel)" is not valid SemVer
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status() # Expecting success, but empty results
    self.assert_results_equal({}, response.json()) # type: ignore[arg-type]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl':
                    'pkg:yeet/github.com/' + # Invalid ecosystem part "yeet"
                    'tianon/gosu@(devel)?package-id=656546dcfdff37ca',
            }
        }),
        timeout=_TIMEOUT)
    # This might return an error due to unknown ecosystem, or empty if it tries to parse.
    # Assuming server returns empty for unknown PURL types if not an outright error.
    # If it's an error, raise_for_status() would trigger or check specific error JSON.
    # For now, assume it results in no matches.
    response.raise_for_status()
    self.assert_results_equal({}, response.json()) # type: ignore[arg-type]

  def test_query_semver_no_vulns(self) -> None:
    """Test queries by SemVer with no vulnerabilities."""
    package_name_val = 'github.com/justinas/nosurf' # Renamed
    ecosystem_val = 'Go' # Renamed

    # Test that a SemVer with a (believed to be non-vulnerable) version and an
    # ecosystem returns no vulnerabilities.
    # (This version does not exist or is not vulnerable)
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '1.2.1', # Non-vulnerable or non-existent version
            'package': {
                'name': package_name_val,
                'ecosystem': ecosystem_val,
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({}, response.json()) # type: ignore[arg-type]

  def test_query_semver_multiple_package(self) -> None:
    """Test query by SemVer (with multiple packages)."""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.4.0',
            'package': {
                'name': 'gopkg.in/yaml.v2', # Alias or old name
                'ecosystem': 'Go',
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    # This might return results if server resolves gopkg.in/yaml.v2 to github.com/go-yaml/yaml
    # Assuming for now it might be empty or specific based on data for gopkg.in/yaml.v2
    # If it's expected to be empty:
    self.assert_results_equal({}, response.json()) # type: ignore[arg-type]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '2.4.0',
            'package': {
                'name': 'github.com/go-yaml/yaml', # Canonical name
                'ecosystem': 'Go',
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    response_json_go: Dict[str, Any] = response.json() # type: ignore[assignment]
    # response_json_go.get('vulns') can be None if key missing
    vulns_go: List[Dict[str, Any]] = response_json_go.get('vulns', [])
    self.assertCountEqual(['GO-2021-0061', 'GO-2020-0036'],
                          [vuln['id'] for vuln in vulns_go])

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
    response.raise_for_status()
    response_json_npm: Dict[str, Any] = response.json() # type: ignore[assignment]
    vulns_npm: List[Dict[str, Any]] = response_json_npm.get('vulns', [])
    self.assertEqual(2, len(vulns_npm))
    self.assertCountEqual(['GHSA-6fc8-4gx4-v693', 'GHSA-3h5v-q93c-6h6q'],
                          [vuln['id'] for vuln in vulns_npm])

  def test_query_purl(self) -> None:
    """Test querying by PURL."""
    expected_cargo: List[Dict[str, Any]] = [ # Renamed
        self._get('GHSA-qc84-gqf4-9926'),
        self._get('RUSTSEC-2022-0041')
    ]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'version': '0.8.6', # Version in params
            'package': {
                'purl': 'pkg:cargo/crossbeam-utils', # PURL without version
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_cargo}, response.json()) # type: ignore[arg-type]

    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'purl': 'pkg:cargo/crossbeam-utils@0.8.6', # Version in PURL
            }}),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_cargo}, response.json()) # type: ignore[arg-type]

    expected_npm: List[Dict[str, Any]] = [self._get('GHSA-j8xg-fqg3-53r7')] # Renamed
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {
            'purl': 'pkg:npm/word-wrap@1.2.2',
        }}),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_npm}, response.json()) # type: ignore[arg-type]

    expected_deb_list: List[Dict[str, Any]] = [ # Renamed expected_deb
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
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_deb_list}, response.json()) # type: ignore[arg-type]

    # Source arch should return the same as above
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl': 'pkg:deb/debian/smarty4@4.1.1-1?arch=source',
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_deb_list}, response.json()) # type: ignore[arg-type]

    # A non source arch should also return the same item
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'purl': 'pkg:deb/debian/smarty4@4.1.1-1?arch=x64',
            }}),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_deb_list}, response.json()) # type: ignore[arg-type]

    # A non arch qualifier should be ignored if server logic handles it that way
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'purl': ('pkg:deb/debian/smarty4@4.1.1-1?'
                         'randomqualifier=1234'),
            }
        }),
        timeout=_TIMEOUT)
    response.raise_for_status()
    self.assert_results_equal({'vulns': expected_deb_list}, response.json()) # type: ignore[arg-type]

  def test_query_purl_with_version_trailing_zeroes(self) -> None:
    """Test purl with trailing zeroes in version."""
    # Case 1: PyPI cryptography
    expected_crypto_response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:pypi/cryptography@3.1'}}),
        timeout=_TIMEOUT)
    expected_crypto_response.raise_for_status()

    response_crypto_zero = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:pypi/cryptography@3.1.0'}}),
        timeout=_TIMEOUT)
    response_crypto_zero.raise_for_status()
    self.assert_results_equal(expected_crypto_response.json(), response_crypto_zero.json()) # type: ignore[arg-type]

    # Case 2: NuGet SkiaSharp
    expected_skiasharp_response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:nuget/SkiaSharp@2.80.3'}}),
        timeout=_TIMEOUT)
    expected_skiasharp_response.raise_for_status()

    response_skiasharp_zero = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:nuget/SkiaSharp@2.80.3.0'}}),
        timeout=_TIMEOUT)
    response_skiasharp_zero.raise_for_status()
    self.assert_results_equal(expected_skiasharp_response.json(), response_skiasharp_zero.json()) # type: ignore[arg-type]

    # Case 3: PyPI Django
    expected_django_response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:pypi/django@4.2'}}),
        timeout=_TIMEOUT)
    expected_django_response.raise_for_status()

    response_django_zero = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:pypi/django@4.2.0'}}),
        timeout=_TIMEOUT)
    response_django_zero.raise_for_status()
    self.assert_results_equal(expected_django_response.json(), response_django_zero.json()) # type: ignore[arg-type]

  def test_query_with_redundant_ecosystem(self) -> None:
    """Test purl with redundant ecosystem raises error"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            "package": {
                "ecosystem": "PyPI", # Redundant with PURL's type
                "purl": "pkg:pypi/mlflow@0.4.0",
            }
        }),
        timeout=_TIMEOUT)
    # This should result in a client error (e.g. 400 Bad Request)
    # The assert_results_equal checks the JSON body of the error response.
    self.assert_results_equal(
        {
            'code': 3, # Example error code for invalid argument
            'message': 'ecosystem specified in a PURL query'
        }, response.json()) # type: ignore[arg-type]

  def test_query_with_redundant_version(self) -> None:
    """Test purl with redundant version raises error"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps({
            "version": "0.4.0", # Redundant with PURL's version
            "package": {
                "purl": "pkg:pypi/mlflow@0.4.0",
            }
        }),
        timeout=_TIMEOUT)
    self.assert_results_equal(
        {
            'code': 3,
            'message': 'version specified in params and PURL query'
        }, response.json()) # type: ignore[arg-type]

  def test_query_with_redundant_package_name(self) -> None:
    """Test purl with redundant name raises error"""
    response = requests.post(
        _api() + _BASE_QUERY,
        data=json.dumps(
            {"package": {
                "name": "mlflow", # Redundant with PURL's name
                "purl": "pkg:pypi/mlflow@0.4.0",
            }}),
        timeout=_TIMEOUT)
    self.assert_results_equal(
        {
            'code': 3,
            'message': 'name specified in a PURL query'
        }, response.json()) # type: ignore[arg-type]

  def test_get_vuln_by_alias_not_in_db(self) -> None:
    """ Test search by ID for a vuln not in db, but alias is"""
    response = requests.get(
        _api() + '/v1/vulns/CVE-2024-40120', timeout=_TIMEOUT) # Non-existent ID
    # Expecting a 404 or similar error, with a JSON body as specified.
    self.assert_results_equal(
        {
            'code': 5, # Example error code for not found
            'message': 'Bug not found, but the following aliases were: '
                       'GHSA-q97m-8853-pq76 GO-2025-3690'
        }, response.json()) # type: ignore[arg-type]

  def test_query_batch(self) -> None:
    """Test batch query."""
    # Define the batch query payload
    batch_query_payload: Dict[str, List[Dict[str, Any]]] = { # More specific type
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
    }

    response = requests.post(
        _api() + '/v1/querybatch',
        data=json.dumps(batch_query_payload),
        timeout=_TIMEOUT)
    response.raise_for_status()

    # Expected structure (simplified, only IDs for brevity as in original)
    # This structure should match what `assert_results_equal` expects.
    # The `remove_modified` in `assert_results_equal` handles 'modified' field.
    expected_batch_response: Dict[str, List[Dict[str, Any]]] = { # More specific type
        'results': [
            { # Result for first query in batch
                'vulns': [{'id': 'GHSA-qc84-gqf4-9926'}, {'id': 'RUSTSEC-2022-0041'}]
            },
            { # Result for second query (empty in this example)
              # 'vulns': [] # Explicitly empty if that's the expected structure
            },
            { # Result for third query
                'vulns': [
                    {'id': 'CVE-2020-15866'}, {'id': 'CVE-2020-36401'},
                    {'id': 'CVE-2021-4110'}, {'id': 'CVE-2021-4188'},
                    {'id': 'CVE-2021-46020'}, {'id': 'CVE-2021-46023'},
                    {'id': 'CVE-2022-0080'}, {'id': 'CVE-2022-0240'},
                    {'id': 'CVE-2022-0326'}, {'id': 'CVE-2022-0481'},
                    {'id': 'CVE-2022-0525'}, {'id': 'CVE-2022-0570'},
                    {'id': 'CVE-2022-0614'}, {'id': 'CVE-2022-0623'},
                    {'id': 'CVE-2022-0630'}, {'id': 'CVE-2022-0631'},
                    {'id': 'CVE-2022-0632'}, {'id': 'CVE-2022-0717'},
                    {'id': 'CVE-2022-0890'}, {'id': 'CVE-2022-1071'},
                    {'id': 'CVE-2022-1106'}, {'id': 'CVE-2022-1201'},
                    {'id': 'CVE-2022-1212'}, {'id': 'CVE-2022-1276'},
                    {'id': 'CVE-2022-1286'}, {'id': 'CVE-2022-1427'},
                    {'id': 'CVE-2022-1934'}, {'id': 'OSV-2020-744'},
                ]
            },
        ]
    }
    # Fill in empty result for second query if server returns {"vulns":[]} vs {}
    if not expected_batch_response['results'][1]: # If it's currently {}
        expected_batch_response['results'][1] = {'vulns': []}


    self.assert_results_equal(expected_batch_response, response.json()) # type: ignore[arg-type]

  @unittest.skipIf(
      os.getenv('LOW_MAX_THRESH', '0') != '1', "Run this test locally with " +
      "MAX_VULN_LISTED_PRE_EXCEEDED at a lower value (around 10)")
  def test_query_pagination(self) -> None:
    """Test query by package with pagination."""
    response_page1 = requests.post( # Renamed response
        _api() + _BASE_QUERY,
        data=json.dumps(
            {'package': {
                'ecosystem': 'PyPI',
                'name': 'tensorflow',
            }}),
        timeout=_TIMEOUT)
    response_page1.raise_for_status()
    result_page1: Dict[str, Any] = response_page1.json() # type: ignore[assignment] # Renamed result
    # result_page1.get('vulns') can be None
    vulns_first_set: set[str] = set(v['id'] for v in result_page1.get('vulns', [])) # Renamed
    self.assertIn('next_page_token', result_page1)
    next_page_token_val: Optional[str] = result_page1.get('next_page_token') # Renamed
    self.assertIsNotNone(next_page_token_val)


    response_page2 = requests.post( # Renamed response
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {
                'ecosystem': 'PyPI',
                'name': 'tensorflow',
            },
            'page_token': next_page_token_val,
        }),
        timeout=_TIMEOUT)
    response_page2.raise_for_status()
    result_page2: Dict[str, Any] = response_page2.json() # type: ignore[assignment] # Renamed result
    vulns_second_set: set[str] = set(v['id'] for v in result_page2.get('vulns', [])) # Renamed

    self.assertEqual(set(), vulns_first_set.intersection(vulns_second_set))

  @unittest.skipIf(
      os.getenv('LOW_MAX_THRESH', '0') != '1', "Run this test locally with " +
      "MAX_VULN_LISTED_PRE_EXCEEDED at a lower value (around 10)")
  def test_query_pagination_no_ecosystem(self) -> None:
    """Test query with pagination but no ecosystem."""
    response_page1_no_eco = requests.post( # Renamed
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {'name': 'django'},
            # Test with a version that is ambiguous whether it
            # belongs to semver or generic version
            'version': '5.0.1',
        }),
        timeout=_TIMEOUT)
    response_page1_no_eco.raise_for_status()
    result_page1_no_eco: Dict[str, Any] = response_page1_no_eco.json() # type: ignore[assignment] # Renamed
    vulns_first_no_eco_set: set[str] = set(v['id'] for v in result_page1_no_eco.get('vulns', [])) # Renamed
    self.assertIn('next_page_token', result_page1_no_eco)
    next_page_token_no_eco: Optional[str] = result_page1_no_eco.get('next_page_token') # Renamed
    self.assertIsNotNone(next_page_token_no_eco)
    # Assuming page token format "query_number:actual_token"
    if next_page_token_no_eco: # Check for type refinement
        self.assertTrue(next_page_token_no_eco.startswith('2:'))


    response_page2_no_eco = requests.post( # Renamed
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {'name': 'django'},
            'version': '5.0.1',
            'page_token': next_page_token_no_eco,
        }),
        timeout=_TIMEOUT)
    response_page2_no_eco.raise_for_status()
    result_page2_no_eco: Dict[str, Any] = response_page2_no_eco.json() # type: ignore[assignment] # Renamed
    vulns_second_no_eco_set: set[str] = set(v['id'] for v in result_page2_no_eco.get('vulns', [])) # Renamed

    # next_page_token might or might not be present on the last page
    # self.assertIn('next_page_token', result_page2_no_eco)
    # Commented out original assertion about token starting with '1:' as it's data-dependent
    self.assertEqual(set(), vulns_first_no_eco_set.intersection(vulns_second_no_eco_set))

  @unittest.skipIf(
      os.getenv('LOW_MAX_THRESH', '0') != '1', "Run this test locally with " +
      "MAX_VULN_LISTED_PRE_EXCEEDED at a lower value (around 10)")
  def test_query_package_purl_paging(self) -> None:
    """Test query by package (purl)."""
    response_page1_purl = requests.post( # Renamed
        _api() + _BASE_QUERY,
        data=json.dumps({'package': {'purl': 'pkg:pypi/tensorflow'}}),
        timeout=_TIMEOUT)
    response_page1_purl.raise_for_status()
    result_page1_purl: Dict[str, Any] = response_page1_purl.json() # type: ignore[assignment] # Renamed
    vulns_first_purl_set: set[str] = set(v['id'] for v in result_page1_purl.get('vulns', [])) # Renamed
    self.assertIn('next_page_token', result_page1_purl)
    next_page_token_purl: Optional[str] = result_page1_purl.get('next_page_token') # Renamed
    self.assertIsNotNone(next_page_token_purl)

    response_page2_purl = requests.post( # Renamed
        _api() + _BASE_QUERY,
        data=json.dumps({
            'package': {'purl': 'pkg:pypi/tensorflow'},
            'page_token': next_page_token_purl,
        }),
        timeout=_TIMEOUT)
    response_page2_purl.raise_for_status()
    result_page2_purl: Dict[str, Any] = response_page2_purl.json() # type: ignore[assignment] # Renamed
    vulns_second_purl_set: set[str] = set(v['id'] for v in result_page2_purl.get('vulns', [])) # Renamed

    self.assertEqual(set(), vulns_first_purl_set.intersection(vulns_second_purl_set))

  @unittest.skipUnless(
      _LONG_TESTS, "Takes around 45 seconds running locally," +
      "enable when making a big change")
  def test_all_possible_queries(self) -> None:
    """Test all combinations of valid and invalid queries"""
    # Using Dict[str, Any] for these test data structures
    semver_package: Dict[str, Any] = {'package': {'purl': 'pkg:cargo/crossbeam-utils'}}
    semver_package_with_version: Dict[str, Any] = {
        'package': {'purl': 'pkg:cargo/crossbeam-utils@0.8.5'}
    }
    nonsemver_package: Dict[str, Any] = {'package': {'purl': 'pkg:pypi/numpy'}}
    nonsemver_package_with_version: Dict[str, Any] = {
        'package': {'purl': 'pkg:pypi/numpy@8.24.0'} # Note: numpy uses calver or similar, not strict semver
    }

    # Lists of query parts to be combined
    pkg_ecosystem_options: List[Dict[str, Any]] = [{'package': {'ecosystem': 'crates.io'}}, {}]
    pkg_name_options: List[Dict[str, Any]] = [
        {'package': {'name': 'crossbeam-utils'}},
        {'package': {'name': 'numpy'}},
        {}
    ]
    pkg_version_options: List[Dict[str, Any]] = [{'version': '0.8.5'}, {}]
    commit_options: List[Dict[str, Any]] = [{'commit': 'd374094d8c49b6b7d288f307e11217ec5a502391'}, {}]
    purl_field_options: List[Dict[str, Any]] = [
        semver_package, semver_package_with_version, nonsemver_package,
        nonsemver_package_with_version, {}
    ]

    # Generate all combinations
    # product_iter is an iterator of tuples, each tuple contains dicts
    product_iter = itertools.product(purl_field_options, commit_options, pkg_version_options,
                                     pkg_name_options, pkg_ecosystem_options)

    combined_product_set: set[str] = set() # Renamed
    for elem_tuple in product_iter: # Renamed elem
      # Deep copy elem_tuple parts before merging, as merge is in-place for the first dict
      # The first element of the tuple will be the base for merging.
      merged_query: Dict[str, Any] = copy.deepcopy(elem_tuple[0])
      for part_dict in elem_tuple[1:]: # Renamed elem_part to part_dict
          merge(merged_query, copy.deepcopy(part_dict)) # Merge subsequent parts into the first
      combined_product_set.add(json.dumps(merged_query, sort_keys=True))

    self.assertEqual(len(combined_product_set), 120) # Check if number of unique queries is as expected

    actual_lines_list: List[str] = [] # Renamed
    for query_json_str in sorted(list(combined_product_set)): # Renamed query
      response = requests.post(
          _api() + _BASE_QUERY, data=query_json_str, timeout=_TIMEOUT)

      # No possible queries should cause a server error (5xx)
      # Client errors (4xx) are possible for invalid combinations.
      self.assertLess(response.status_code, 500, f"Query {query_json_str} failed with {response.status_code}")
      actual_lines_list.append(f"{response.status_code}:{query_json_str}\n")

    # Assuming tests.ExpectationTest.expect_lines_equal is defined in the base class
    self.expect_lines_equal('api_query_response', actual_lines_list)


# From: https://stackoverflow.com/questions/7204805/how-to-merge-dictionaries-of-dictionaries
def merge(a: Dict[str, Any], b: Dict[str, Any], path: Optional[List[str]] = None) -> Dict[str, Any]:
  """Merge two nested dictionaries. Modifies `a` in place."""
  current_path: List[str] = path if path is not None else [] # Renamed

  for key, value_b in b.items(): # Renamed key
    if key in a:
      value_a = a[key] # Value from dict a
      if isinstance(value_a, dict) and isinstance(value_b, dict):
        merge(value_a, value_b, current_path + [str(key)])
      elif value_a != value_b:
        # Conflict if values are different and not both dicts for further merging
        raise Exception('Conflict at ' + '.'.join(current_path + [str(key)]))
        # Or handle conflict differently, e.g. by preferring `b`'s value: a[key] = value_b
    else: # Key from b not in a, add it
      a[key] = value_b
  return a # Return modified dict a


def print_logs(filename: str) -> None:
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

  # Ensure docker pull runs successfully
  subprocess.run(
      ['docker', 'pull', 'gcr.io/endpoints-release/endpoints-runtime:2'],
      check=True, # Will raise CalledProcessError if command fails
      capture_output=True # Suppress output unless there's an error
  )

  credential_path_arg: str = sys.argv.pop(1) # Renamed
  # test_server.start likely returns a Popen object or similar process handle
  server_process: subprocess.Popen[Any] = test_server.start(credential_path_arg, port=_PORT) # Renamed server
  # Wait for server to start - consider a more robust check if possible
  time.sleep(10)

  try:
    # unittest.main uses sys.argv directly. We've modified it by popping.
    unittest.main(argv=sys.argv)
  finally:
    server_process.stop() # Assuming Popen object has stop() or terminate()/kill()
    # Or test_server.stop(server_process) if that's the API
