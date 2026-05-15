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
"""Ecosystem helper tests."""

import unittest
from .. import ecosystems


class EcosystemTest(unittest.TestCase):
  """Ecosystem helper tests."""

  def test_add_matching_ecosystems(self):
    """Test sort key"""
    # Test Ubuntu
    ubuntu_ecosystem = {
        'Ubuntu', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04:LTS', 'Ubuntu:24.04:LTS',
        'Ubuntu:24.10', 'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS',
        'Ubuntu:Pro:18.04:LTS'
    }
    actual_output = list(ecosystems.add_matching_ecosystems(ubuntu_ecosystem))
    expected_output = [
        'Ubuntu', 'Ubuntu:14.04', 'Ubuntu:16.04', 'Ubuntu:18.04',
        'Ubuntu:20.04', 'Ubuntu:20.04:LTS', 'Ubuntu:22.04', 'Ubuntu:22.04:LTS',
        'Ubuntu:24.04', 'Ubuntu:24.04:LTS', 'Ubuntu:24.10',
        'Ubuntu:Pro:14.04:LTS', 'Ubuntu:Pro:16.04:LTS', 'Ubuntu:Pro:18.04:LTS'
    ]
    actual_output.sort()
    self.assertEqual(list(actual_output), expected_output)

    #Test Debian (it should be no change)
    debian_ecosystem = {'Debian', 'Debian:11', 'Debian:12', 'Debian:13'}
    actual_output = list(ecosystems.add_matching_ecosystems(debian_ecosystem))
    expected_output = ['Debian', 'Debian:11', 'Debian:12', 'Debian:13']
    actual_output.sort()
    self.assertEqual(list(actual_output), expected_output)

  def test_maybe_normalize_package_names(self):
    """Test normalize package name"""
    package_name = 'Flask'
    ecosystem = 'PyPI'
    expected = 'flask'

    actual = ecosystems.maybe_normalize_package_names(package_name, ecosystem)
    self.assertEqual(actual, expected)

  def test_maybe_normalize_package_names_echo_pypi(self):
    """Test that Echo:PyPI uses PyPI package name normalization"""
    self.assertEqual(
        ecosystems.maybe_normalize_package_names('My_Package', 'Echo:PyPI'),
        'my-package')
    self.assertEqual(
        ecosystems.maybe_normalize_package_names('Flask', 'Echo:PyPI'), 'flask')

  def test_echo_pypi_ecosystem(self):
    """Test that Echo:PyPI uses PyPI version ordering"""
    self.assertTrue(ecosystems.is_known('Echo'))
    self.assertTrue(ecosystems.is_known('Echo:PyPI'))

    echo_pypi = ecosystems.get('Echo:PyPI')
    self.assertIsNotNone(echo_pypi)

    # PyPI version ordering
    self.assertLess(echo_pypi.sort_key('1.0.0'), echo_pypi.sort_key('1.0.1'))
    self.assertLess(echo_pypi.sort_key('1.0.0a1'), echo_pypi.sort_key('1.0.0'))
    self.assertLess(echo_pypi.sort_key('1.0.0rc1'), echo_pypi.sort_key('1.0.0'))
    self.assertLess(echo_pypi.sort_key('1.9'), echo_pypi.sort_key('1.10'))

  def test_echo_base_ecosystem(self):
    """Test that plain Echo uses Debian version ordering"""
    echo = ecosystems.get('Echo')
    self.assertIsNotNone(echo)

    self.assertLess(echo.sort_key('1.0'), echo.sort_key('1.1'))
    self.assertLess(echo.sort_key('1.0~rc1'), echo.sort_key('1.0'))

  def test_root_ecosystem(self):
    """Test Root ecosystem"""
    # Test that Root ecosystem is recognized
    self.assertTrue(ecosystems.is_known('Root'))
    self.assertTrue(ecosystems.is_known('Root:Alpine:3.18'))
    self.assertTrue(ecosystems.is_known('Root:Debian:12'))
    self.assertTrue(ecosystems.is_known('Root:PyPI'))

    # Test that Root ecosystem can be retrieved
    root = ecosystems.get('Root')
    self.assertIsNotNone(root)

    # Test version sorting for different Root version formats
    root_alpine = ecosystems.get('Root:Alpine:3.18')
    self.assertIsNotNone(root_alpine)

    # Alpine format: -rXXXXX
    self.assertLess(
        root_alpine.sort_key('1.0.0-r10071'),
        root_alpine.sort_key('1.0.0-r10072'))
    self.assertLess(
        root_alpine.sort_key('1.0.0-r10071'),
        root_alpine.sort_key('2.0.0-r10071'))

    # Python format: +root.io.X
    root_pypi = ecosystems.get('Root:PyPI')
    self.assertIsNotNone(root_pypi)
    self.assertLess(
        root_pypi.sort_key('1.0.0+root.io.1'),
        root_pypi.sort_key('1.0.0+root.io.2'))

    # Other format: .root.io.X
    root_debian = ecosystems.get('Root:Debian:12')
    self.assertIsNotNone(root_debian)
    self.assertLess(
        root_debian.sort_key('1.0.0.root.io.1'),
        root_debian.sort_key('1.0.0.root.io.2'))

  def test_tuxcare_ecosystem(self):
    """Test TuxCare ecosystem delegates to inner ecosystem parsers."""
    # TuxCare:<ecosystem> should be recognized when the inner ecosystem is.
    self.assertTrue(ecosystems.is_known('TuxCare:Red Hat'))
    self.assertTrue(ecosystems.is_known('TuxCare:AlmaLinux'))
    self.assertTrue(ecosystems.is_known('TuxCare:Debian'))
    self.assertTrue(ecosystems.is_known('TuxCare:npm'))
    self.assertTrue(ecosystems.is_known('TuxCare:Alpine:v3.16'))
    self.assertTrue(ecosystems.is_known('TuxCare:Ubuntu:22.04:LTS'))
    # Inner ecosystems known in the schema but without implementations are
    # still "known".
    self.assertTrue(ecosystems.is_known('TuxCare:Android'))
    # Unknown inner ecosystem.
    self.assertFalse(ecosystems.is_known('TuxCare:NotARealEcosystem'))
    # Bare TuxCare is malformed.
    self.assertFalse(ecosystems.is_known('TuxCare'))
    self.assertFalse(ecosystems.is_known('TuxCare:'))
    # Nested TuxCare is malformed (loop guard).
    self.assertFalse(ecosystems.is_known('TuxCare:TuxCare'))
    self.assertFalse(ecosystems.is_known('TuxCare:TuxCare:Red Hat'))

    # get() returns the inner ecosystem helper.
    tuxcare_rpm = ecosystems.get('TuxCare:Red Hat')
    self.assertIsNotNone(tuxcare_rpm)
    # Sort behaviour matches the underlying RPM parser.
    plain_rpm = ecosystems.get('Red Hat')
    self.assertEqual(
        tuxcare_rpm.sort_key('1.2.3-1.el8'), plain_rpm.sort_key('1.2.3-1.el8'))
    self.assertLess(
        tuxcare_rpm.sort_key('1.0.0-1'), tuxcare_rpm.sort_key('1.0.1-1'))

    # Suffixes pass through to the inner ecosystem.
    tuxcare_alpine = ecosystems.get('TuxCare:Alpine:v3.16')
    self.assertIsNotNone(tuxcare_alpine)
    self.assertEqual(tuxcare_alpine.inner.suffix, 'v3.16')

    # Inner ecosystem with multi-segment suffix (e.g. Ubuntu variants).
    tuxcare_ubuntu = ecosystems.get('TuxCare:Ubuntu:Pro:18.04:LTS')
    self.assertIsNotNone(tuxcare_ubuntu)
    self.assertEqual(tuxcare_ubuntu.inner.suffix, 'Pro:18.04:LTS')

    # Bare TuxCare returns None.
    self.assertIsNone(ecosystems.get('TuxCare'))
    self.assertIsNone(ecosystems.get('TuxCare:'))
    # Nested TuxCare returns None (no infinite recursion).
    self.assertIsNone(ecosystems.get('TuxCare:TuxCare'))
    self.assertIsNone(ecosystems.get('TuxCare:TuxCare:Red Hat'))
