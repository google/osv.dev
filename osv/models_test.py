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
"""Models tests."""

import unittest

from . import models
from . import tests

from google.cloud import ndb


class ModelsTest(unittest.TestCase):
  """Tests for ndb Model migrations."""

  def setUp(self):
    models.SourceRepository(
        id='test',
        name='test',
        db_prefix=['TEST-'],
    ).put()
    return super().setUp()

  def test_normalize_repo(self):
    """Test normalize_repo_package function."""
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

        # .git suffix removed
        ('https://github.com/user/repo.git', 'github.com/user/repo'),
        ('http://git.example.com/repo.git', 'git.example.com/repo'),

        # edge cases
        ('', ''),
        ('invalid-url', 'invalid-url'),
        ('http://', ''),
        ('https://hostname', 'hostname'),
    ]

    for repo_url, expected in test_cases:
      with self.subTest(repo_url=repo_url):
        self.assertEqual(expected, models.normalize_repo_package(repo_url))


def setUpModule():
  """Set up the test module."""
  # Start the emulator BEFORE creating the ndb client
  unittest.enterModuleContext(tests.datastore_emulator())
  unittest.enterModuleContext(ndb.Client().context(cache_policy=False))


if __name__ == '__main__':
  unittest.main()
