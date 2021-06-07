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


class GitRemoteCallback(pygit2.RemoteCallbacks):
  """Authentication callbacks."""

  def __init__(self, username, ssh_key_public_path, ssh_key_private_path):
    super().__init__()
    self.username = username
    self.ssh_key_public_path = ssh_key_public_path
    self.ssh_key_private_path = ssh_key_private_path

  def credentials(self, url, username_from_url, allowed_types):
    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_USERNAME:
      return pygit2.Username(self.username)

    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_SSH_KEY:
      return pygit2.Keypair(self.username, self.ssh_key_public_path,
                            self.ssh_key_private_path, '')

    return None


def clone(git_url, checkout_dir, callbacks=None):
  """Perform a clone."""
  # Use 'git' CLI here as it's much faster than libgit2's clone.
  env = {}
  if callbacks:
    env['GIT_SSH_COMMAND'] = (
        f'ssh -i "{callbacks.ssh_key_private_path}" '
        f'-o User={callbacks.username} -o IdentitiesOnly=yes')

  subprocess.check_call(['git', 'clone', git_url, checkout_dir], env=env)
  return pygit2.Repository(checkout_dir)


def clone_with_retries(git_url, checkout_dir, callbacks=None):
  """Clone with retries."""
  logging.info('Cloning %s to %s', git_url, checkout_dir)
  for _ in range(CLONE_TRIES):
    try:
      repo = clone(git_url, checkout_dir, callbacks)
      repo.cache = {}
      return repo
    except (pygit2.GitError, subprocess.CalledProcessError) as e:
      logging.error('Clone failed: %s', str(e))
      shutil.rmtree(checkout_dir, ignore_errors=True)
      time.sleep(RETRY_SLEEP_SECONDS)
      continue

  return None


def _use_existing_checkout(git_url, checkout_dir, git_callbacks):
  """Update and use existing checkout."""
  repo = pygit2.Repository(checkout_dir)
  repo.cache = {}
  if repo.remotes['origin'].url != git_url:
    raise RuntimeError('Repo URL changed.')
  repo.cache = {}

  reset_repo(repo, git_callbacks)
  logging.info('Using existing checkout at %s', checkout_dir)
  return repo


def ensure_updated_checkout(git_url, checkout_dir, git_callbacks=None):
  """Ensure updated checkout."""
  if os.path.exists(checkout_dir):
    # Already exists, reset and checkout latest revision.
    try:
      return _use_existing_checkout(git_url, checkout_dir, git_callbacks)
    except Exception as e:
      # Failed to re-use existing checkout. Delete it and start over.
      logging.error('Failed to load existing checkout: %s', e)
      shutil.rmtree(checkout_dir)

  repo = clone_with_retries(git_url, checkout_dir, git_callbacks)
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
