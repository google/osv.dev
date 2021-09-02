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
"""SemVer index tests."""

import unittest

import semver

import semver_index


class SemverIndexTests(unittest.TestCase):
  """SemVer index tests."""

  def test_coerce(self):
    """Test coerce."""
    self.assertEqual('1.0.0', semver_index.coerce('1'))
    self.assertEqual('1.0.0', semver_index.coerce('v1'))
    self.assertEqual('1.0.0', semver_index.coerce('v1.0'))
    self.assertEqual('1.0.0', semver_index.coerce('1.0.0'))

    self.assertEqual('1.5.0', semver_index.coerce('1.5'))
    self.assertEqual('1.5.0', semver_index.coerce('v1.5'))
    self.assertEqual('1.5.0', semver_index.coerce('v1.5.0'))
    self.assertEqual('1.5.1', semver_index.coerce('1.5.1'))

    self.assertEqual('', semver_index.coerce(''))
    self.assertEqual('rubbish', semver_index.coerce('rubbish'))
    self.assertEqual('a1.0.0', semver_index.coerce('a1.0.0'))
    self.assertEqual('1.0.0.0', semver_index.coerce('1.0.0.0'))
    self.assertEqual('1.0.0-foo', semver_index.coerce('1.0.0-foo'))
    self.assertEqual('1-foo', semver_index.coerce('1-foo'))

  def test_normalize(self):
    """Test version normalization."""
    versions = [
        '1.0.0-beta.2+BLAH', '1.0.0-beta.2', '1.0.0-beta.11', '1.0.0-rc.1',
        '1.0.0', '1.0.0-alpha', '1.0.0-alpha.1', '1.0.0-alpha.beta',
        '1.0.0-beta', '1.0.0-9', '1.0.0-0a',
        '24.4.3001-20191109021931-daa7c04131f5'
    ]

    self.assertListEqual([
        '00000001.00000000.00000000-1beta.00000002',
        '00000001.00000000.00000000-1beta.00000002',
        '00000001.00000000.00000000-1beta.00000011',
        '00000001.00000000.00000000-1rc.00000001',
        '00000001.00000000.00000000-zzzzzzzzzzzzzzzz',
        '00000001.00000000.00000000-1alpha',
        '00000001.00000000.00000000-1alpha.00000001',
        '00000001.00000000.00000000-1alpha.1beta',
        '00000001.00000000.00000000-1beta',
        '00000001.00000000.00000000-00000009', '00000001.00000000.00000000-10a',
        '00000024.00000004.00003001-120191109021931-daa7c04131f5'
    ], [semver_index.normalize(version) for version in versions])

  def test_sort(self):
    """Test sorting."""
    versions = [
        '1.0.2', '1.0.11', '1.9.0', '1.11.0',
        '1.0.1-20191109021931-daa7c04131f5',
        '1.0.1-pre.0.20191109021931-daa7c04131f5',
        '1.0.1-0.20191109021931-daa7c04131f5', '1.0.1-beta.2', '1.0.1-beta.11',
        '1.0.1-rc.1', '1.0.1', '1.0.1-alpha', '1.0.1-alpha.1',
        '1.0.1-alpha.beta', '1.0.1-beta', '1.0.1-9', '1.0.1-0a'
    ]

    self.assertListEqual([
        '1.0.1-0.20191109021931-daa7c04131f5',
        '1.0.1-9',
        '1.0.1-0a',
        '1.0.1-20191109021931-daa7c04131f5',
        '1.0.1-alpha',
        '1.0.1-alpha.1',
        '1.0.1-alpha.beta',
        '1.0.1-beta',
        '1.0.1-beta.2',
        '1.0.1-beta.11',
        '1.0.1-pre.0.20191109021931-daa7c04131f5',
        '1.0.1-rc.1',
        '1.0.1',
        '1.0.2',
        '1.0.11',
        '1.9.0',
        '1.11.0',
    ], sorted(versions, key=semver_index.normalize))

    # Sanity check that the python semver library agrees.
    self.assertListEqual(
        sorted(versions, key=semver.VersionInfo.parse),
        sorted(versions, key=semver_index.normalize))


if __name__ == '__main__':
  unittest.main()
