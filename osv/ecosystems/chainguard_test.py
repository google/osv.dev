# Copyright 2024 Google LLC
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
"""Chainguard ecosystem helper tests."""

import unittest
from .. import ecosystems
from .helper_base import Ecosystem


class ChainguardEcosystemTest(unittest.TestCase):
  """Chainguard ecosystem helper tests."""

  def test_chainguard(self) -> None:
    """Test sort_key"""
    ecosystem: Ecosystem = ecosystems.get('Chainguard')
    self.assertIsNotNone(ecosystem)
    self.assertGreater(
        ecosystem.sort_key('38.52.0-r0'),  # pytype: disable=attribute-error
        ecosystem.sort_key('37.52.0-r0'))  # pytype: disable=attribute-error
    self.assertLess(ecosystem.sort_key('453'), ecosystem.sort_key('453-r1'))  # pytype: disable=attribute-error
    self.assertGreater(ecosystem.sort_key('5.4.13-r1'), ecosystem.sort_key('0'))  # pytype: disable=attribute-error
    self.assertGreater(
        ecosystem.sort_key('1.4.0-r1'),  # pytype: disable=attribute-error
        ecosystem.sort_key('1.4.0-r0'))  # pytype: disable=attribute-error
    self.assertGreater(
        ecosystem.sort_key('invalid'),  # pytype: disable=attribute-error
        ecosystem.sort_key('1.4.0-r0'))  # pytype: disable=attribute-error
