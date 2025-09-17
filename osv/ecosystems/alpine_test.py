# Copyright 2025 Google LLC
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
"""APK / Alpine ecosystem helper tests."""

import os
import unittest
from unittest import mock
import warnings

from . import alpine

from .. import cache
from .. import ecosystems
from .. import repos


class APKEcosystemTest(unittest.TestCase):
  """APK ecosystem helper tests."""

  def test_apk(self):
    """Test APK ecosystem sort_key behaviour"""
    ecosystem = alpine.APK()

    # Alpine
    # Should not throw exception
    ecosystem.sort_key('1.9.5p2')
    ecosystem.sort_key('1.9.5p2-r0')

    self.assertGreater(
        ecosystem.sort_key('1.9.5p3'), ecosystem.sort_key('1.9.5p2'))
    self.assertGreater(
        ecosystem.sort_key('1.9.5p1'), ecosystem.sort_key('1.9.5'))

    self.assertGreater(
        ecosystem.sort_key('1.13.2-r0'), ecosystem.sort_key('1.13.2_alpha'))

    # Check invalid version handle
    self.assertGreater(
        ecosystem.sort_key('1-0-0'), ecosystem.sort_key('1.13.2-r0'))
    self.assertEqual(
        ecosystem.sort_key('1.13.2-r0'), ecosystem.sort_key('1.13.2-r0'))

    # Chainguard
    self.assertGreater(
        ecosystem.sort_key('38.52.0-r0'), ecosystem.sort_key('37.52.0-r0'))
    self.assertLess(ecosystem.sort_key('453'), ecosystem.sort_key('453-r1'))
    self.assertGreater(ecosystem.sort_key('5.4.13-r1'), ecosystem.sort_key('0'))
    self.assertGreater(
        ecosystem.sort_key('1.4.0-r1'), ecosystem.sort_key('1.4.0-r0'))
    self.assertGreater(
        ecosystem.sort_key('invalid'), ecosystem.sort_key('1.4.0-r0'))

    # MinimOS
    self.assertGreater(
        ecosystem.sort_key('38.52.0-r0'), ecosystem.sort_key('37.52.0-r0'))
    self.assertLess(ecosystem.sort_key('453'), ecosystem.sort_key('453-r1'))
    self.assertGreater(ecosystem.sort_key('5.4.13-r1'), ecosystem.sort_key('0'))
    self.assertGreater(
        ecosystem.sort_key('1.4.0-r1'), ecosystem.sort_key('1.4.0-r0'))
    self.assertGreater(
        ecosystem.sort_key('invalid'), ecosystem.sort_key('1.4.0-r0'))
    self.assertGreater(
        ecosystem.sort_key('13.0.14.5-r1'), ecosystem.sort_key('7.64.3-r2'))
    self.assertLess(
        ecosystem.sort_key('13.0.14.5-r1'), ecosystem.sort_key('16.6-r0'))

    # Check >= / <= methods: https://github.com/google/osv.dev/pull/3978
    self.assertGreaterEqual(
        ecosystem.sort_key('1.10.0-r0'), ecosystem.sort_key('1.2.0-r0'))
    self.assertLessEqual(
        ecosystem.sort_key('1.2.0-r0'), ecosystem.sort_key('1.10.0-r0'))

  def test_apk_ecosystems(self):
    """Test apk-based ecosystems return an APK ecosystem."""
    ecos = [
        'Alpine',
        'Alpaquita',
        'BellSoft Hardened Containers',
        'Chainguard',
        'MinimOS',
        'Wolfi',
    ]
    for ecosystem_name in ecos:
      ecosystem = ecosystems.get(ecosystem_name)
      self.assertIsInstance(ecosystem, alpine.APK)


class AlpineEcosystemTest(unittest.TestCase):
  """Alpine ecosystem helper tests."""
  _TEST_DATA_DIR = os.path.join(
      os.path.dirname(os.path.abspath(__file__)), 'testdata')

  @mock.patch(
      'osv.repos.ensure_updated_checkout',
      side_effect=repos.ensure_updated_checkout)
  def test_alpine(self, ensure_updated_checkout_mock: mock.MagicMock):
    """Test Alpine ecosystem enumeration and caching behaviour"""
    in_memory_cache = cache.InMemoryCache()
    ecosystems.config.set_cache(in_memory_cache)

    # Set work_dir to allow cloning/fetching
    ecosystems.config.work_dir = self._TEST_DATA_DIR
    ecosystem = ecosystems.get('Alpine:v3.16')
    self.assertEqual(ensure_updated_checkout_mock.call_count, 0)
    # Tests that next version and version enumeration generally works
    with warnings.catch_warnings():
      # Filter the DeprecationWarning from next_version
      warnings.filterwarnings('ignore', 'Avoid using this method')
      self.assertEqual('1.12.2-r1', ecosystem.next_version('nginx', '1.12.2'))
      self.assertEqual(ensure_updated_checkout_mock.call_count, 1)
      self.assertEqual('1.16.1-r0',
                       ecosystem.next_version('nginx', '1.16.0-r4'))
      # Second call should use cache, so call count should not increase
      self.assertEqual(ensure_updated_checkout_mock.call_count, 1)

      # Check letter suffixes clone correctly
      self.assertEqual('2.78c-r0',
                       ecosystem.next_version('blender', '2.78a-r1'))

    ecosystems.config.set_cache(None)
