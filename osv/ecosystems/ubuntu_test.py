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
from .. import ecosystems


class UbuntuEcosystemTest(unittest.TestCase):
  """Ubuntu ecosystem helper tests."""

  def test_ubuntu(self):
    ecosystem = ecosystems.get('Ubuntu')
    self.assertGreater(
        ecosystem.sort_key('2.42.8+dfsg-1ubuntu0.3'),
        ecosystem.sort_key('2.40.0+dfsg-3ubuntu0.5'))
    self.assertGreater(
        ecosystem.sort_key('2.42.8+dfsg-1ubuntu0.3'),
        ecosystem.sort_key('2.42.8+dfsg-1ubuntu0.2'))
    self.assertGreater(ecosystem.sort_key('5.4.13-1'), ecosystem.sort_key('0'))
    self.assertGreater(
        ecosystem.sort_key('5.4.13-1'), ecosystem.sort_key('3.2.30-1'))
    self.assertGreater(
        ecosystem.sort_key('invalid'), ecosystem.sort_key('3.2.30-1'))
