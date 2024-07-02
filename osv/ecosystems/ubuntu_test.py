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
"""Ubuntu ecosystem helper tests."""

import unittest
from unittest import mock

from osv.ecosystems.ubuntu import compare


class UbuntuEcosystemTest(unittest.TestCase):
  """Ubuntu ecosystem helper tests."""
  # def test_ubuntu(self):
    # val = compare("2.40.0+dfsg-3ubuntu0.5", "2.42.8+dfsg-1ubuntu0.3")
    # self.assertEqual(val, -1)

    # val = compare("999999.99999.99999", "5.4.13-1")
    # self.assertEqual(val, 1)

    # val = compare("0", "5.4.13-1")
    # self.assertEqual(val, -1)

    # val = compare("3.2.30-1", "5.4.13-1")
    # self.assertEqual(val, -1)