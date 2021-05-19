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
import time

import pygit2

CLONE_TRIES = 3
RETRY_SLEEP_SECONDS = 5


def clone_with_retries(git_url, checkout_dir, callbacks=None):
  """Clone with retries."""
  logging.info('Cloning %s to %s', git_url, checkout_dir)
  for _ in range(CLONE_TRIES):
    try:
      repo = pygit2.clone_repository(git_url, checkout_dir, callbacks=callbacks)
      repo.cache = {}
      return repo
    except pygit2.GitError as e:
      logging.error('Clone failed: %s', str(e))
      time.sleep(RETRY_SLEEP_SECONDS)
      continue

  return None


def _use_existing_checkout(git_url, checkout_dir, git_callbacks):
  """Update and use existing checkout."""
  repo = pygit2.Repository(checkout_dir)
  if repo.remotes['origin'].url != git_url:
    raise RuntimeError('Repo URL changed.')

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
