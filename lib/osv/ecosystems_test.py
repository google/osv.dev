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

  def test_gems(self):
    ecosystem = ecosystems.get('RubyGems')
    self.assertEqual('0.8.0', ecosystem.next_version('rails', '0'))
    self.assertEqual('0.9.5', ecosystem.next_version('rails', '0.9.4.1'))
    self.assertEqual('2.3.8.pre1', ecosystem.next_version('rails', '2.3.7'))
    self.assertEqual('4.0.0.rc1',
                     ecosystem.next_version('rails', '4.0.0.beta1'))
    self.assertEqual('5.0.0.racecar1',
                     ecosystem.next_version('rails', '5.0.0.beta4'))

  def test_nuget(self):
    ecosystem = ecosystems.get('NuGet')
    self.assertEqual('3.0.1',
                     ecosystem.next_version('NuGet.Server.Core', '3.0.0'))
    self.assertEqual('3.0.0.4001',
                     ecosystem.next_version('Castle.Core', '3.0.0.3001'))
    self.assertEqual('3.1.0-RC',
                     ecosystem.next_version('Castle.Core', '3.0.0.4001'))
    self.assertEqual('2.1.0-dev-00668',
                     ecosystem.next_version('Serilog', '2.1.0-dev-00666'))

  def test_semver(self):
    ecosystem = ecosystems.get('Go')
    self.assertEqual('1.0.1-0', ecosystem.next_version('blah', '1.0.0'))
    self.assertEqual('1.0.0-pre.0', ecosystem.next_version('blah', '1.0.0-pre'))


if __name__ == '__main__':
  unittest.main()
