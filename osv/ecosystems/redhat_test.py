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
"""RPM / Red Hat Linux ecosystem helper tests."""

import unittest

from . import redhat

from .. import ecosystems


class RPMEcosystemTest(unittest.TestCase):
  """RPM ecosystem helper tests."""

  def test_rpm(self):
    """Test sort_key"""
    ecosystem = redhat.RPM()
    # Red Hat
    self.assertGreater(
        ecosystem.sort_key('0:0.2.6-20.module+el8.9.0+1420+91577025'),
        ecosystem.sort_key('0:0.0.99.4-5.module+el8.9.0+1445+07728297'))
    self.assertGreater(
        ecosystem.sort_key('0:0.2.6-20.module+el8.9.0+1420+91577025'),
        ecosystem.sort_key('0'))
    self.assertGreater(
        ecosystem.sort_key('2:1.14.3-2.module+el8.10.0+1815+5fe7415e'),
        ecosystem.sort_key('2:1.10.3-1.module+el8.10.0+1815+5fe7415e'))
    self.assertLess(ecosystem.sort_key('invalid'), ecosystem.sort_key('0'))

    # AlmaLinux
    self.assertGreater(
        ecosystem.sort_key("9.27-15.el8_10"),
        ecosystem.sort_key("9.27-13.el8_10"))
    self.assertGreater(
        ecosystem.sort_key("9.27-15.el8_10"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("3:2.1.10-1.module_el8.10.0+3858+6ad51f9f"),
        ecosystem.sort_key("3:2.1.10-1.module_el8.10.0+3845+87b84552"))
    self.assertLess(
        ecosystem.sort_key("20230404-117.git2e92a49f.el8_8.alma.1"),
        ecosystem.sort_key("20240111-121.gitb3132c18.el8"))
    self.assertEqual(
        ecosystem.sort_key("20240111-121.gitb3132c18.el8"),
        ecosystem.sort_key("20240111-121.gitb3132c18.el8"))

    # Mageia
    self.assertGreater(
        ecosystem.sort_key('3.2.7-1.2.mga9'),
        ecosystem.sort_key('3.2.7-1.mga9'))
    self.assertGreater(
        ecosystem.sort_key('3.2.7-1.2.mga9'), ecosystem.sort_key('0'))
    self.assertLess(ecosystem.sort_key('invalid'), ecosystem.sort_key('0'))
    self.assertGreater(
        ecosystem.sort_key('1:1.8.11-1.mga9'),
        ecosystem.sort_key('0:1.9.1-2.mga9'))

    # openEuler
    self.assertGreater(
        ecosystem.sort_key("1.2.3-1.oe2203"),
        ecosystem.sort_key("1.2.2-1.oe2203"))
    self.assertGreater(
        ecosystem.sort_key("2.0.0-1.oe2203"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("1.2.3-2.oe2203"),
        ecosystem.sort_key("1.2.3-1.oe2203"))
    self.assertLess(
        ecosystem.sort_key("1.2.2-1.oe2203"),
        ecosystem.sort_key("1.2.3-1.oe2203"))
    self.assertEqual(
        ecosystem.sort_key("1.2.3-1.oe2203"),
        ecosystem.sort_key("1.2.3-1.oe2203"))

    # openSUSE
    self.assertGreater(
        ecosystem.sort_key("4.2-lp151.4.3.1"),
        ecosystem.sort_key("1.5.1-lp151.4.3.1"))
    self.assertGreater(
        ecosystem.sort_key("4.9.6-bp152.2.3.1"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("6.2.8-bp156.2.3.1"),
        ecosystem.sort_key("6.2.8-bp156"))
    self.assertLess(
        ecosystem.sort_key("0.4.6-15.8"), ecosystem.sort_key("1.4.6-15.8"))
    self.assertEqual(
        ecosystem.sort_key("6.2.8-bp156.2.3.1"),
        ecosystem.sort_key("6.2.8-bp156.2.3.1"))

    # SUSE
    self.assertGreater(
        ecosystem.sort_key("2.38.5-150400.4.34.2"),
        ecosystem.sort_key("2.37.5-150400.4.34.2"))
    self.assertGreater(
        ecosystem.sort_key("2.0.8-4.8.2"), ecosystem.sort_key("0"))
    self.assertGreater(
        ecosystem.sort_key("2.0.8_k4.12.14_10.118-4.8.2"),
        ecosystem.sort_key("2.0.8-4.8.2"))
    self.assertLess(
        ecosystem.sort_key("1.86-150100.7.23.11"),
        ecosystem.sort_key("2.86-150100.7.23.1"))
    self.assertEqual(
        ecosystem.sort_key("2.0.8-4.8.2"), ecosystem.sort_key("2.0.8-4.8.2"))

    # Check >= / <= methods
    self.assertGreaterEqual(
        ecosystem.sort_key('1.10.2-1.oe2203'),
        ecosystem.sort_key('1.2.2-1.oe2203'))
    self.assertLessEqual(
        ecosystem.sort_key('1.2.2-1.oe2203'),
        ecosystem.sort_key('1.10.2-1.oe2203'))

  def test_rpm_ecosystems(self):
    """Test RPM-based ecosystems return an RPM ecosystem."""
    ecos = [
        'Red Hat',
        'AlmaLinux',
        'Mageia',
        'openEuler',
        'openSUSE',
        'Rocky Linux',
        'SUSE',
    ]
    for ecosystem_name in ecos:
      ecosystem = ecosystems.get(ecosystem_name)
      self.assertIsInstance(ecosystem, redhat.RPM)
