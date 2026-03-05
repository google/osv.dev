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

from server import should_skip_bucket


class ServerTest(unittest.TestCase):
  """Server tests."""

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
