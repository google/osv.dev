# Copyright 2025 Google LLC
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
"""Root ecosystem helper tests."""

import unittest

from . import root


class RootEcosystemTest(unittest.TestCase):
  """Root ecosystem helper tests."""

  def test_alpine_versions(self):
    """Test Root:Alpine version comparison."""
    ecosystem = root.Root(suffix=':Alpine:3.18')

    # Basic Alpine version ordering
    self.assertGreater(
        ecosystem.sort_key('1.51.0-r20072'),
        ecosystem.sort_key('1.51.0-r20071'))
    self.assertGreater(
        ecosystem.sort_key('1.0.0-r2'), ecosystem.sort_key('1.0.0-r1'))

    # Check the 0 sentinel value
    self.assertLess(ecosystem.sort_key('0'), ecosystem.sort_key('1.0.0-r1'))

    # Check equality
    self.assertEqual(
        ecosystem.sort_key('1.51.0-r20071'),
        ecosystem.sort_key('1.51.0-r20071'))

  def test_debian_versions(self):
    """Test Root:Debian version comparison."""
    ecosystem = root.Root(suffix=':Debian:12')

    # Basic Debian version ordering with Root suffix
    self.assertGreater(
        ecosystem.sort_key('22.12.0-2+deb12u1.root.io.5'),
        ecosystem.sort_key('22.12.0-2.root.io.1'))

    self.assertGreater(
        ecosystem.sort_key('1.18.0-6+deb11u3-r20072'),
        ecosystem.sort_key('1.18.0-6+deb11u3-r20071'))

    # Check equality
    self.assertEqual(
        ecosystem.sort_key('1.18.0-6+deb11u3-r20071'),
        ecosystem.sort_key('1.18.0-6+deb11u3-r20071'))

  def test_ubuntu_versions(self):
    """Test Root:Ubuntu version comparison."""
    ecosystem = root.Root(suffix=':Ubuntu:22.04')

    # Ubuntu version ordering
    self.assertGreater(
        ecosystem.sort_key('1.2.3-4ubuntu2'),
        ecosystem.sort_key('1.2.3-4ubuntu1'))

  def test_pypi_versions(self):
    """Test Root:PyPI version comparison."""
    ecosystem = root.Root(suffix=':PyPI')

    # Python version ordering with Root suffix
    self.assertGreater(
        ecosystem.sort_key('1.0.0+root.io.5'),
        ecosystem.sort_key('1.0.0+root.io.1'))

    # PEP440 version ordering
    self.assertGreater(ecosystem.sort_key('2.0.0'), ecosystem.sort_key('1.9.9'))
    self.assertGreater(
        ecosystem.sort_key('1.0.0'), ecosystem.sort_key('1.0.0rc1'))

  def test_npm_versions(self):
    """Test Root:npm version comparison."""
    ecosystem = root.Root(suffix=':npm')

    # npm semver ordering with Root suffix
    self.assertGreater(
        ecosystem.sort_key('1.0.0.root.io.5'),
        ecosystem.sort_key('1.0.0.root.io.1'))

    # Basic semver ordering
    self.assertGreater(ecosystem.sort_key('2.0.0'), ecosystem.sort_key('1.9.9'))
    self.assertGreater(ecosystem.sort_key('1.0.1'), ecosystem.sort_key('1.0.0'))

  def test_maven_versions(self):
    """Test Root:Maven version comparison."""
    ecosystem = root.Root(suffix=':Maven')

    # Maven version ordering
    self.assertGreater(ecosystem.sort_key('2.0'), ecosystem.sort_key('1.0'))
    self.assertGreater(
        ecosystem.sort_key('1.0'), ecosystem.sort_key('1.0-SNAPSHOT'))

  def test_unknown_ecosystem_fallback(self):
    """Test fallback behavior for unknown ecosystems."""
    ecosystem = root.Root(suffix=None)

    # Should still work with Alpine-like versions
    self.assertGreater(
        ecosystem.sort_key('1.0.0-r2'), ecosystem.sort_key('1.0.0-r1'))

    # Should work with generic versions
    self.assertGreater(ecosystem.sort_key('2.0.0'), ecosystem.sort_key('1.0.0'))

  def test_github_issue_4396(self):
    """Test the specific versions from GitHub issue #4396."""
    ecosystem = root.Root(suffix=':Debian:12')

    # The problematic comparison that used to crash
    key1 = ecosystem.sort_key('22.12.0-2.root.io.1')
    key2 = ecosystem.sort_key('22.12.0-2+deb12u1.root.io.5')

    # Should not crash and should compare correctly
    self.assertLess(key1, key2)

  def test_root_suffix_extraction(self):
    """Test extraction of Root-specific version suffixes."""
    ecosystem = root.Root(suffix=':PyPI')

    # Python format: +root.io.<number>
    key = ecosystem.sort_key('1.0.0+root.io.5')
    self.assertIsNotNone(key)

    # Generic format: .root.io.<number>
    key = ecosystem.sort_key('1.0.0.root.io.5')
    self.assertIsNotNone(key)

  def test_invalid_versions(self):
    """Test that invalid versions raise appropriate errors."""
    # Alpine ecosystem with invalid version
    ecosystem_alpine = root.Root(suffix=':Alpine:3.18')
    key = ecosystem_alpine.sort_key('invalid-version!@#')
    self.assertTrue(key.is_invalid)

    # Debian ecosystem with empty version
    ecosystem_debian = root.Root(suffix=':Debian:12')
    key = ecosystem_debian.sort_key('')
    self.assertTrue(key.is_invalid)

  def test_sub_ecosystem_extraction(self):
    """Test _get_sub_ecosystem method."""
    # Test various suffix formats
    # pylint: disable=protected-access
    ecosystem = root.Root(suffix=':Alpine:3.18')
    self.assertEqual(ecosystem._get_sub_ecosystem(), 'Alpine')

    ecosystem = root.Root(suffix=':Debian:12')
    self.assertEqual(ecosystem._get_sub_ecosystem(), 'Debian')

    ecosystem = root.Root(suffix=':npm')
    self.assertEqual(ecosystem._get_sub_ecosystem(), 'npm')

    ecosystem = root.Root(suffix=None)
    self.assertEqual(ecosystem._get_sub_ecosystem(), 'unknown')


if __name__ == '__main__':
  unittest.main()
