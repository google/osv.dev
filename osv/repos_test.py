import contextlib
import os
import unittest
import shutil
import tempfile
from . import repos
from . import tests

class ReposTest(unittest.TestCase):

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    self.enterContext(tests.setup_gitter())

  def tearDown(self):
    shutil.rmtree(self.tmp_dir)

  def test_clone_non_existent_repo(self):
    # This repo should not exist and thus return 404/403 (git usually asks for auth for private/missing repos)
    # causing gitter to return 403
    url = 'https://github.com/google/osv.dev-non-existent-repo-12345'
    checkout_dir = os.path.join(self.tmp_dir, 'checkout')
    
    with self.assertRaises(repos.RepoInaccessibleError):
      repos.clone(url, checkout_dir)

if __name__ == '__main__':
  unittest.main()
