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

from . import purl_helpers


class PurlHelpersTest(unittest.TestCase):
  """purl_helpers tests."""

  def test_pypi(self):
    """Test PURL generation for PyPI."""
    self.assertEqual('pkg:pypi/django',
                     purl_helpers.package_to_purl('PyPI', 'django'))

  def test_maven(self):
    """Test PURL generation for Maven."""
    self.assertEqual(
        'pkg:maven/org.apache.struts/struts2-core',
        purl_helpers.package_to_purl('Maven', 'org.apache.struts:struts2-core'))

  def test_npm(self):
    """Test PURL generation for npm."""
    self.assertEqual('pkg:npm/%40hapi/hoek',
                     purl_helpers.package_to_purl('npm', '@hapi/hoek'))

  def test_debian(self):
    """Test PURL generation for npm."""
    self.assertEqual('pkg:deb/debian/nginx?arch=source',
                     purl_helpers.package_to_purl('Debian', 'nginx'))

  def test_alpine(self):
    """Test PURL generation for alpine."""
    self.assertEqual('pkg:apk/alpine/nginx?arch=source',
                     purl_helpers.package_to_purl('Alpine', 'nginx'))

  def test_pub(self):
    """Test PURL generation for Pub."""
    self.assertEqual('pkg:pub/characters',
                     purl_helpers.package_to_purl('Pub', 'characters'))

  def test_pub(self):
    """Test PURL generation for Swift."""
    self.assertEqual('pkg:swift/github.com/Alamofire/Alamofire',
                     purl_helpers.package_to_purl('SwiftURL', 'github.com/Alamofire/Alamofire'))


if __name__ == '__main__':
  unittest.main()
