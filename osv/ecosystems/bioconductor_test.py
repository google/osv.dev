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

import unittest

from .. import ecosystems


class BioconductorEcosystemTest(unittest.TestCase):
  """Bioconductor ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('Bioconductor')
    self.assertEqual('1.18.0', ecosystem.next_version('a4', '1.16.0'))
    self.assertEqual('1.20.0', ecosystem.next_version('a4', '1.18.0'))
    with self.assertRaises(ecosystems.EnumerateError):
      ecosystem.next_version('doesnotexist123456', '1')
