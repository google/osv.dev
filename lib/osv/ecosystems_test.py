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
"""Bug helper tests."""

import unittest

from . import ecosystems


class GetNextVersionTest(unittest.TestCase):
  """get_next_version tests."""

  def test_pypi(self):
    ecosystem = ecosystems.get('PyPI')
    self.assertEqual('1.36.0rc1', ecosystem.next_version('grpcio', '1.35.0'))
    self.assertEqual('1.36.1', ecosystem.next_version('grpcio', '1.36.0'))
    self.assertEqual('0.3.0', ecosystem.next_version('grpcio', '0'))

  def test_maven(self):
    ecosystem = ecosystems.get('Maven')
    self.assertEqual('1.36.0',
                     ecosystem.next_version('io.grpc:grpc-core', '1.35.1'))
    self.assertEqual('0.7.0', ecosystem.next_version('io.grpc:grpc-core', '0'))

  def test_semver(self):
    ecosystem = ecosystems.get('Go')
    self.assertEqual('1.0.1-0', ecosystem.next_version('blah', '1.0.0'))
    self.assertEqual('1.0.0-pre.0', ecosystem.next_version('blah', '1.0.0-pre'))


if __name__ == '__main__':
  unittest.main()
