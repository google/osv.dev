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

from server import should_skip_bucket, _normalize_git_repo_url


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

  def test_normalize_git_repo_url(self):
    """Test _normalize_git_repo_url function."""
    test_cases = [
        # protocol normalization
        ('http://git.musl-libc.org/git/musl', 'git.musl-libc.org/git/musl'),
        ('https://git.musl-libc.org/git/musl', 'git.musl-libc.org/git/musl'),
        ('git://git.musl-libc.org/git/musl', 'git.musl-libc.org/git/musl'),

        # github examples
        ('http://github.com/user/repo', 'github.com/user/repo'),
        ('https://github.com/user/repo', 'github.com/user/repo'),
        ('git://github.com/user/repo', 'github.com/user/repo'),

        # trailing slash
        ('https://github.com/user/repo/', 'github.com/user/repo'),
        ('http://git.example.com/path/', 'git.example.com/path'),

        # .git suffix preserved
        ('https://github.com/user/repo.git', 'github.com/user/repo.git'),
        ('http://git.example.com/repo.git', 'git.example.com/repo.git'),

        # edge cases
        ('', ''),
        ('invalid-url', 'invalid-url'),
        ('http://', ''),
        ('https://hostname', 'hostname'),
    ]

    for repo_url, expected in test_cases:
      with self.subTest(repo_url=repo_url):
        self.assertEqual(expected, _normalize_git_repo_url(repo_url))


if __name__ == '__main__':
  unittest.main()
