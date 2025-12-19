import os
import unittest
import shutil
import tempfile
from . import repos
from . import tests

class ReposTest(unittest.TestCase):

  def setUp(self):
    self.tmp_dir = tempfile.mkdtemp()
    # Pick a random port or just use a fixed one for now, hopefully 9999 is free
    self.gitter_port = 8889
    self.gitter_host = f'http://localhost:{self.gitter_port}'
    os.environ['GITTER_HOST'] = self.gitter_host
    # Update GITTER_HOST in repos module since it might have been loaded already
    repos.GITTER_HOST = self.gitter_host
    
    # Start gitter
    try:
      self.gitter_cleanup = tests.setup_gitter('GITTER_HOST')
    except Exception as e:
      self.fail(f"Failed to setup gitter: {e}")

  def tearDown(self):
    if hasattr(self, 'gitter_cleanup'):
      self.gitter_cleanup()
    shutil.rmtree(self.tmp_dir)
    os.environ.pop('GITTER_HOST', None)

  def test_clone_non_existent_repo(self):
    # This repo should not exist and thus return 404/403 (git usually asks for auth for private/missing repos)
    # causing gitter to return 403
    url = 'https://github.com/google/osv.dev-non-existent-repo-12345'
    checkout_dir = os.path.join(self.tmp_dir, 'checkout')
    
    with self.assertRaises(repos.RepoInaccessibleError):
      repos.clone(url, checkout_dir)

if __name__ == '__main__':
  unittest.main()
