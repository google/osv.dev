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
"""Repo functions."""

import logging
import os
import shutil
import subprocess
import time

import pygit2

CLONE_TRIES = 3
RETRY_SLEEP_SECONDS = 5

# More performant mirrors for large/popular repos.
# TODO: Don't hardcode this.
_GIT_MIRRORS = {
    'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git':
        'https://kernel.googlesource.com/pub/scm/'
        'linux/kernel/git/stable/linux.git'
}


class GitRemoteCallback(pygit2.RemoteCallbacks):
  """Authentication callbacks."""

  def __init__(self, username, ssh_key_public_path, ssh_key_private_path):
    super().__init__()
    self.username = username
    self.ssh_key_public_path = ssh_key_public_path
    self.ssh_key_private_path = ssh_key_private_path

  def credentials(self, url, username_from_url, allowed_types):
    """Get credentials."""
    del url
    del username_from_url

    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_USERNAME:
      return pygit2.Username(self.username)

    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_SSH_KEY:
      return pygit2.Keypair(self.username, self.ssh_key_public_path,
                            self.ssh_key_private_path, '')

    return None


def _git_mirror(git_url):
  """Get git mirror. If no mirror exists, return the git URL as is."""
  mirror = _GIT_MIRRORS.get(git_url.rstrip('/'))
  if mirror:
    logging.info('Using mirror %s for git URL %s.', mirror, git_url)
    return mirror

  return git_url


def _checkout_branch(repo, branch):
  """Check out a branch."""
  remote_branch = repo.lookup_branch('origin/' + branch,
                                     pygit2.GIT_BRANCH_REMOTE)
  local_branch = repo.lookup_branch(branch, pygit2.GIT_BRANCH_LOCAL)
  if not local_branch:
    local_branch = repo.branches.create(branch, commit=remote_branch.peel())

  local_branch.upstream = remote_branch
  local_branch.set_target(remote_branch.target)
  repo.checkout(local_branch)
  repo.reset(remote_branch.target, pygit2.GIT_RESET_HARD)


def clone(git_url, checkout_dir, git_callbacks=None):
  """Perform a clone."""
  # Use 'git' CLI here as it's much faster than libgit2's clone.
  env = {}
  if git_callbacks:
    env['GIT_SSH_COMMAND'] = (
        f'ssh -i "{git_callbacks.ssh_key_private_path}" '
        f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'-o User={git_callbacks.username} -o IdentitiesOnly=yes')

  subprocess.check_call(
      ['git', 'clone', _git_mirror(git_url), checkout_dir], env=env)
  return pygit2.Repository(checkout_dir)


def clone_with_retries(git_url, checkout_dir, git_callbacks=None, branch=None):
  """Clone with retries."""
  logging.info('Cloning %s to %s', git_url, checkout_dir)
  for _ in range(CLONE_TRIES):
    try:
      repo = clone(git_url, checkout_dir, git_callbacks)
      repo.cache = {}
      if branch:
        _checkout_branch(repo, branch)
      return repo
    except (pygit2.GitError, subprocess.CalledProcessError) as e:
      logging.error('Clone failed: %s', str(e))
      shutil.rmtree(checkout_dir, ignore_errors=True)
      time.sleep(RETRY_SLEEP_SECONDS)
      continue

  return None


def _use_existing_checkout(git_url,
                           checkout_dir,
                           git_callbacks=None,
                           branch=None):
  """Update and use existing checkout."""
  repo = pygit2.Repository(checkout_dir)
  repo.cache = {}
  if repo.remotes['origin'].url != _git_mirror(git_url):
    raise RuntimeError('Repo URL changed.')

  if branch:
    _checkout_branch(repo, branch)

  reset_repo(repo, git_callbacks)
  logging.info('Using existing checkout at %s', checkout_dir)
  return repo


def ensure_updated_checkout(git_url,
                            checkout_dir,
                            git_callbacks=None,
                            branch=None):
  """Ensure updated checkout."""
  if os.path.exists(checkout_dir):
    # Already exists, reset and checkout latest revision.
    try:
      return _use_existing_checkout(
          git_url, checkout_dir, git_callbacks=git_callbacks, branch=branch)
    except Exception as e:
      # Failed to re-use existing checkout. Delete it and start over.
      logging.error('Failed to load existing checkout: %s', e)
      shutil.rmtree(checkout_dir)

  repo = clone_with_retries(
      git_url, checkout_dir, git_callbacks=git_callbacks, branch=branch)
  logging.info('Repo now at: %s', repo.head.peel().message)
  return repo


def reset_repo(repo, git_callbacks):
  """Reset repo."""
  repo.remotes['origin'].fetch(callbacks=git_callbacks)
  remote_branch = repo.lookup_branch(
      repo.head.name.replace('refs/heads/', 'origin/'),
      pygit2.GIT_BRANCH_REMOTE)

  # Reset to remote branch.
  repo.head.set_target(remote_branch.target)
  repo.reset(remote_branch.target, pygit2.GIT_RESET_HARD)
