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
"""CRAN ecosystem helper tests."""

import vcr.unittest

from .. import ecosystems
from .helper_base import Ecosystem


class CRANEcosystemTest(vcr.unittest.VCRTestCase):
  """CRAN ecosystem helper tests."""

  def test_next_version(self) -> None:
    """Test next_version."""
    ecosystem: Ecosystem = ecosystems.get('CRAN')
    self.assertIsNotNone(ecosystem)
    # Test typical semver X.Y.Z version
    self.assertEqual('0.1.1', ecosystem.next_version('readxl', '0.1.0'))  # pytype: disable=attribute-error
    self.assertEqual('1.0.0', ecosystem.next_version('readxl', '0.1.1'))  # pytype: disable=attribute-error

    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')  # pytype: disable=attribute-error

    # Test versions with the X.Y-Z format
    self.assertEqual('0.1-18', ecosystem.next_version('abd', '0.1-12'))  # pytype: disable=attribute-error
    self.assertEqual('0.2-2', ecosystem.next_version('abd', '0.1-22'))  # pytype: disable=attribute-error

    # Test atypical versioned package
    self.assertEqual('0.99-8.47', ecosystem.next_version('aqp', '0.99-8.1'))  # pytype: disable=attribute-error
