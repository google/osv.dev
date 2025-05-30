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
"""Bioconductor ecosystem helper tests."""

import vcr.unittest

from .. import ecosystems
from .helper_base import Ecosystem


class BioconductorEcosystemTest(vcr.unittest.VCRTestCase):
  """Bioconductor ecosystem helper tests."""

  def test_next_version(self) -> None:
    """Test next_version."""
    ecosystem: Ecosystem = ecosystems.get('Bioconductor')
    self.assertIsNotNone(ecosystem)
    self.assertEqual('1.18.0', ecosystem.next_version('a4', '1.16.0'))  # pytype: disable=attribute-error
    self.assertEqual('1.20.0', ecosystem.next_version('a4', '1.18.0'))  # pytype: disable=attribute-error
    self.assertGreater(ecosystem.sort_key('1-0'), ecosystem.sort_key('1.2.0'))  # pytype: disable=attribute-error
    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')  # pytype: disable=attribute-error
