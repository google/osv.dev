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
"""Alma Linux ecosystem helper tests."""

import unittest

from osv.ecosystems.rocky_linux import compare


class RockyLinuxEcosystemTest(unittest.TestCase):
  """Rocky Alma linux ecosystem helper tests."""
  # def test_alma_linux(self):
  #   val = compare("9.27-13.el8_10", "9.27-15.el8_10")
  #   self.assertEqual(val, -1)