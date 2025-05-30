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
"""Alpine ecosystem helper tests."""

import os
import unittest
from unittest import mock

from .. import cache
from .. import ecosystems
from .. import repos
from .helper_base import Ecosystem


class AlpineEcosystemTest(unittest.TestCase):
  """Alpine ecosystem helper tests."""
  _TEST_DATA_DIR: str = os.path.join(
      os.path.dirname(os.path.abspath(__file__)), 'testdata')

  @mock.patch(
      'osv.repos.ensure_updated_checkout',
      side_effect=repos.ensure_updated_checkout)
  def test_alpine(self,
                  ensure_updated_checkout_mock: mock.MagicMock) -> None:
    """Test Alpine ecosystem enumeration and caching behaviour"""
    in_memory_cache = cache.InMemoryCache()
    ecosystems.config.set_cache(in_memory_cache) # pytype: disable=module-attr

    # Set work_dir to allow cloning/fetching
    ecosystems.config.work_dir = self._TEST_DATA_DIR # pytype: disable=module-attr
    ecosystem: Ecosystem = ecosystems.get('Alpine:v3.16')
    self.assertIsNotNone(ecosystem)
    self.assertEqual(ensure_updated_checkout_mock.call_count, 0)
    # Tests that next version and version enumeration generally works
    self.assertEqual('1.12.2-r1', ecosystem.next_version('nginx', '1.12.2')) # pytype: disable=attribute-error
    self.assertEqual(ensure_updated_checkout_mock.call_count, 1)
    self.assertEqual('1.16.1-r0', ecosystem.next_version('nginx', '1.16.0-r4')) # pytype: disable=attribute-error
    # Second call should use cache, so call count should not increase
    self.assertEqual(ensure_updated_checkout_mock.call_count, 1)

    # Should not throw exception
    ecosystem.sort_key('1.9.5p2') # pytype: disable=attribute-error
    ecosystem.sort_key('1.9.5p2-r0') # pytype: disable=attribute-error

    self.assertGreater(
        ecosystem.sort_key('1.9.5p3'), ecosystem.sort_key('1.9.5p2')) # pytype: disable=attribute-error
    self.assertGreater(
        ecosystem.sort_key('1.9.5p1'), ecosystem.sort_key('1.9.5')) # pytype: disable=attribute-error

    # Check letter suffixes clone correctly
    self.assertEqual('2.78c-r0', ecosystem.next_version('blender', '2.78a-r1')) # pytype: disable=attribute-error

    self.assertGreater(
        ecosystem.sort_key('1.13.2-r0'), ecosystem.sort_key('1.13.2_alpha')) # pytype: disable=attribute-error

    # Check invalid version handle
    self.assertGreater(
        ecosystem.sort_key('1-0-0'), ecosystem.sort_key('1.13.2-r0')) # pytype: disable=attribute-error

    ecosystems.config.set_cache(None) # pytype: disable=module-attr
