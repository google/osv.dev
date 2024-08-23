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
"""Debian ecosystem helper tests."""

import requests
import unittest
from unittest import mock

from .. import cache
from .. import ecosystems


@unittest.skip(
    "snapshot.debian.org certificate expiry: https://bugs.debian.org/1079320")
class DebianEcosystemTest(unittest.TestCase):
  """Debian ecosystem helper tests."""

  @mock.patch(
      'osv.request_helper.requests.Session.get',
      side_effect=requests.Session.get,
      autospec=True)
  @mock.patch('osv.ecosystems.debian.requests.get', side_effect=requests.get)
  def test_debian(self, first_ver_requests_mock: mock.MagicMock,
                  general_requests_mock: mock.MagicMock):
    """Test Debian ecosystem enumeration and caching behaviour"""
    in_memory_cache = cache.InMemoryCache()
    ecosystems.config.set_cache(in_memory_cache)
    ecosystem = ecosystems.get('Debian:9')

    # Tests that next version and version enumeration generally works
    self.assertEqual('1.13.6-1', ecosystem.next_version('nginx', '1.13.5-1'))
    self.assertEqual('1.13.6-2', ecosystem.next_version('nginx', '1.13.6-1'))
    self.assertEqual('3.0.1+dfsg-2',
                     ecosystem.next_version('blender', '3.0.1+dfsg-1'))

    # Tests that sort key works
    self.assertGreater(
        ecosystem.sort_key('1.13.6-2'), ecosystem.sort_key('1.13.6-1'))

    # Test that <end-of-life> specifically is greater than normal versions
    self.assertGreater(
        ecosystem.sort_key('<end-of-life>'), ecosystem.sort_key('1.13.6-1'))

    # Test that end-of-life enumeration is disabled
    with self.assertLogs(level='WARNING') as logs:
      self.assertEqual(
          ecosystem.enumerate_versions('nginx', '0', '<end-of-life>'), [])
    self.assertEqual(logs.output, ['WARNING:root:Package nginx has invalid fixed version: <end-of-life>. In debian release 9'])  # pylint: disable=line-too-long

    # Calls for first_version to the same ecosystem should be cached
    self.assertEqual(first_ver_requests_mock.call_count, 1)
    ecosystem.enumerate_versions('htop', '0')

    self.assertEqual(first_ver_requests_mock.call_count, 1)

    # Now start testing that Debian:10 contains different versions compared to 9
    ecosystem = ecosystems.get('Debian:10')

    # Called 2 times so far, once for nginx, once for blender.
    self.assertEqual(general_requests_mock.call_count, 3)
    # '0' as introduced version also tests the get_first_package_version func
    versions = ecosystem.enumerate_versions('cyrus-sasl2', '0', None)
    self.assertEqual(general_requests_mock.call_count, 4)

    # new ecosystem, first version requests increase by 1
    self.assertEqual(first_ver_requests_mock.call_count, 2)

    # Check that only deb10 versions are in Debian:10, and no deb9 versions
    self.assertIn('2.1.27+dfsg-1+deb10u1', versions)
    self.assertNotIn('2.1.27~101-g0780600+dfsg-3+deb9u1', versions)
    self.assertNotIn('2.1.27~101-g0780600+dfsg-3+deb9u2', versions)

    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')

    self.assertEqual(general_requests_mock.call_count, 5)

    # This should now only call the cache, and not requests.get
    ecosystem.enumerate_versions('cyrus-sasl2', '0', None)
    self.assertEqual(first_ver_requests_mock.call_count, 2)
    self.assertEqual(general_requests_mock.call_count, 5)
    ecosystems.config.set_cache(None)

  def test_debian_sort_key(self):
    """Tests Debian sort key across different releases."""
    ecosystem = ecosystems.get('Debian')

    # Compares base versions
    self.assertGreater(ecosystem.sort_key('1.2.3'), ecosystem.sort_key('1.2'))
    self.assertGreater(ecosystem.sort_key('1.3'), ecosystem.sort_key('1.2-3'))

    # Compares versions within the same Debian release
    self.assertGreater(
        ecosystem.sort_key('1.3+deb11u1'), ecosystem.sort_key('1.2+deb11u5'))

    # Compare versions across Debian releases
    self.assertGreater(
        ecosystem.sort_key('1.2+deb12u1'),
        ecosystem.sort_key('1.2+deb11u2'))  # deb12 > deb11
    self.assertGreater(
        ecosystem.sort_key('1.18+deb11u3'),
        ecosystem.sort_key('1.14+deb10u3'))  # 1.18 > 1.14
    self.assertGreater(
        ecosystem.sort_key('1.18+deb10'),
        ecosystem.sort_key('1.14+deb11'))  # 1.18 > 1.14

  @mock.patch('osv.cache.Cache')
  def test_cache(self, cache_mock: mock.MagicMock):
    cache_mock.get.return_value = None
    ecosystems.config.set_cache(cache_mock)

    debian = ecosystems.get('Debian:9')
    debian.next_version('nginx', '1.13.5-1')
    cache_mock.get.assert_called_once()
    cache_mock.set.assert_called_once()
