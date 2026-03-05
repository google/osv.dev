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
"""Repo tests."""
import os
import unittest
import shutil
import tempfile
from . import repos
from . import tests


class ReposTest(unittest.TestCase):
  """Repo tests."""

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    self.enterContext(tests.setup_gitter())

  def tearDown(self):
    shutil.rmtree(self.tmp_dir)

  def test_clone_non_existent_repo(self):
    """Test cloning a non-existent repo."""
    # This repo should not exist and thus return 404/403 (git usually asks for
    # auth for private/missing repos) causing gitter to return 403.
    url = 'https://github.com/google/osv.dev-non-existent-repo-12345'
    checkout_dir = os.path.join(self.tmp_dir, 'checkout')

    with self.assertRaises(repos.RepoInaccessibleError):
      repos.clone(url, checkout_dir)


if __name__ == '__main__':
  unittest.main()
