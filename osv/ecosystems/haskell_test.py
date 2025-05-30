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

import vcr.unittest

from .. import ecosystems
from .helper_base import Ecosystem


class HackageEcosystemTest(vcr.unittest.VCRTestCase):
  """Hackage ecosystem helper tests."""

  def test_next_version(self) -> None:
    """Test next_version."""
    ecosystem: Ecosystem = ecosystems.get('Hackage')
    self.assertIsNotNone(ecosystem)
    self.assertEqual('1.0.0.0', ecosystem.next_version('aeson', '0.11.3.0'))  # pytype: disable=attribute-error
    self.assertEqual('1.0.1.0', ecosystem.next_version('aeson', '1.0.0.0'))  # pytype: disable=attribute-error
    self.assertEqual('0.1.26.0', ecosystem.next_version('jose', '0'))  # pytype: disable=attribute-error
    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')  # pytype: disable=attribute-error

  def test_sort_key(self) -> None:
    """Test sort_key."""
    ecosystem: Ecosystem = ecosystems.get('Hackage')
    self.assertIsNotNone(ecosystem)
    self.assertGreater(  # pytype: disable=attribute-error
        ecosystem.sort_key('1-20-0'), ecosystem.sort_key('1.20.0'))


class GHCEcosystemTest(vcr.unittest.VCRTestCase):
  """GHC ecosystem helper tests."""

  def test_next_version(self) -> None:
    """Test next_version."""
    ecosystem: Ecosystem = ecosystems.get('GHC')
    self.assertIsNotNone(ecosystem)
    self.assertEqual('0.29', ecosystem.next_version('GHC', '0'))  # pytype: disable=attribute-error
    self.assertEqual('7.0.4', ecosystem.next_version('GHC', '7.0.4-rc1'))  # pytype: disable=attribute-error
    # 7.0.4 is the last of the hardcoded versions
    self.assertEqual('7.2.1', ecosystem.next_version('GHC', '7.0.4'))  # pytype: disable=attribute-error

    # The whole GHC ecosystem is versioned together.  Enumeration ignores
    # package/component name.  Therefore this should NOT raise:
    ecosystem.next_version('doesnotexist123456', '1')  # pytype: disable=attribute-error
