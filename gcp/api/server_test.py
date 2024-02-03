# Copyright 2023 Google LLC
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
"""Server unit tests."""

import unittest

from server import _match_purl
from server import should_skip_bucket
from packageurl import PackageURL


class ServerTest(unittest.TestCase):
  """Server tests."""

  def test_match_purl(self):
    """Test PURL generation for PyPI."""

    test_cases = [
        # Version diffs are ignored
        ('pkg:pypi/django', 'pkg:pypi/django@1.2.3', True),
        ('pkg:deb/debian/nginx@1.14.2-2+deb10u3',
         'pkg:deb/debian/nginx@1.14.2-2+deb10u4', True),
        # Different packages do not match
        ('pkg:deb/debian/busybox@1.14.2-2+deb10u3',
         'pkg:deb/debian/nginx@1.14.2-2+deb10u3', False),
        ('pkg:deb/debian/nginx@1.14.2-2+deb10u3?arch=amd64',
         'pkg:deb/debian/nginx@1.14.2-2?arch=source', True),
        ('pkg:deb/debian/nginx@1.14.2-2+deb10u3?distro=debian-10',
         'pkg:deb/debian/nginx@1.14.2-2?arch=source', True),
    ]

    for a, b, expected in test_cases:
      self.assertEqual(
          expected,
          _match_purl(PackageURL.from_string(a), PackageURL.from_string(b)),
          a + ' == ' + b)

  def test_should_skip_bucket(self):
    """Test should_skip_bucket."""
    test_cases = [
        (None, False),
        ('', False),
        ('/a', False),
        ('a', False),
        ('a/b', False),
        ('a/b/c', False),
        ('/a/b/c', False),
        ('/a/3rdparty/c', True),
        ('/a/third_party/c/d', True),
        ('/third_party/c/d', True),
        ('vendor/c/d', True),
        ('/a/3rdpartyy/c', False),
    ]

    for path, expected in test_cases:
      self.assertEqual(expected, should_skip_bucket(path))


if __name__ == '__main__':
  unittest.main()
