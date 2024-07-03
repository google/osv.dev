# Copyright 2021 Google LLC
# Copyright 2023 Fraser Tweedale
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
"""Haskell ecosystem helper tests."""

import unittest

from .. import ecosystems


class HackageEcosystemTest(unittest.TestCase):
  """Hackage ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('Hackage')
    self.assertEqual('1.0.0.0', ecosystem.next_version('aeson', '0.11.3.0'))
    self.assertEqual('1.0.1.0', ecosystem.next_version('aeson', '1.0.0.0'))
    self.assertEqual('0.1.26.0', ecosystem.next_version('jose', '0'))
    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')


class GHCEcosystemTest(unittest.TestCase):
  """GHC ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('GHC')
    self.assertEqual('0.29', ecosystem.next_version('GHC', '0'))
    self.assertEqual('7.0.4', ecosystem.next_version('GHC', '7.0.4-rc1'))
    # 7.0.4 is the last of the hardcoded versions
    # Disabled due to https://github.com/google/osv.dev/issues/2367
    # self.assertEqual('7.2.1', ecosystem.next_version('GHC', '7.0.4'))

    # The whole GHC ecosystem is versioned together.  Enumeration ignores
    # package/component name.  Therefore this should NOT raise:
    ecosystem.next_version('doesnotexist123456', '1')
