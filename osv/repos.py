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
import datetime
import logging
import os
import shutil
import subprocess
import time
import requests

import pygit2
import pygit2.enums

CLONE_TRIES = int(os.getenv('CLONE_TRIES', '3'))
RETRY_SLEEP_SECONDS = 5

# More performant mirrors for large/popular repos.
# TODO: Don't hardcode this.
_GIT_MIRRORS = {
    'https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git':
        'https://kernel.googlesource.com/pub/scm/'
        'linux/kernel/git/stable/linux.git'
}

FETCH_CACHE: dict[tuple, datetime.datetime] = {}
FETCH_CACHE_SECONDS = 5 * 60  # 5 minutes

GITTER_HOST = os.getenv('GITTER_HOST', '')


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
    if allowed_types & pygit2.enums.CredentialType.USERNAME:
      return pygit2.Username(self.username)

    if allowed_types & pygit2.CredentialType.SSH_KEY:
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
                                     pygit2.enums.BranchType.REMOTE)
  local_branch = repo.lookup_branch(branch, pygit2.enums.BranchType.LOCAL)
  if not local_branch:
    if remote_branch is None:
      raise NoBranchError
    local_branch = repo.branches.create(branch, commit=remote_branch.peel())

  local_branch.upstream = remote_branch
  local_branch.set_target(remote_branch.target)
  repo.checkout(local_branch)
  repo.reset(remote_branch.target, pygit2.enums.ResetMode.HARD)


def _set_git_callback_env(git_callbacks):
  """Set the environment variable to set git callbacks for cli git"""
  env = {
      # Prevent prompting for username if we don't have an ssh key
      'GIT_TERMINAL_PROMPT': '0'
  }
  if git_callbacks:
    env['GIT_SSH_COMMAND'] = (
        f'ssh -i "{git_callbacks.ssh_key_private_path}" '
        f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'-o User={git_callbacks.username} -o IdentitiesOnly=yes')
  return env


class GitCloneError(Exception):
  """Git repository clone exception."""


class NoBranchError(Exception):
  """Branch does not exist"""


class RepoInaccessibleError(Exception):
  """Git repository cannot be cloned due to being deleted or requiring auth."""


def clone(git_url, checkout_dir, git_callbacks=None, blobless=False):
  """Perform a clone."""
  # Don't user Gitter for oss-fuzz-vulns repo because it requires auth
  if GITTER_HOST and git_url != 'ssh://github.com/google/oss-fuzz-vulns':
    try:
      os.makedirs(checkout_dir, exist_ok=True)
      resp = requests.get(
          f'{GITTER_HOST}/getgit',
          params={'url': _git_mirror(git_url)},
          stream=True,
          timeout=3600
      )  # Long timeout duration (1hr) because it could be cloning a large repo
      if resp.status_code == 403:
        raise RepoInaccessibleError()
      if resp.status_code == 400:
        raise GitCloneError(f'Failed to clone repo: {resp.text}')

      resp.raise_for_status()

      with open(f'{checkout_dir}.zst', 'wb') as f:
        shutil.copyfileobj(resp.raw, f)

      cmd = ['tar', '-xf', f'{checkout_dir}.zst', '-C', checkout_dir]
      subprocess.run(cmd, check=True)
      # Remove after extraction.
      os.remove(f'{checkout_dir}.zst')

      return pygit2.Repository(checkout_dir)
    except requests.RequestException as e:
      raise GitCloneError(f'Failed to clone repo: {e}') from e
    except subprocess.CalledProcessError as e:
      raise GitCloneError(f'Failed to unarchive repo:\n{e}') from e
    except pygit2.GitError as e:
      raise GitCloneError('Failed to open cloned repo') from e

  try:
    # Use 'git' CLI here as it's much faster than libgit2's clone.
    env = _set_git_callback_env(git_callbacks)
    cmd = ['git', 'clone']
    if blobless:
      cmd.append('--filter=blob:none')
    cmd.extend([_git_mirror(git_url), checkout_dir])
    subprocess.run(cmd, env=env, capture_output=True, check=True)
    return pygit2.Repository(checkout_dir)
  except subprocess.CalledProcessError as e:
    stderr = e.stderr.decode(errors='ignore')
    if ('could not read Username' in stderr or
        ('fatal: repository' in stderr and 'not found' in stderr) or
        'Authentication failed' in stderr):
      # Git is asking for username/password, the repository doesn't exist, or
      # authentication failed.
      raise RepoInaccessibleError() from e
    raise GitCloneError(f'Failed to clone repo:\n{stderr}') from e
  except pygit2.GitError as e:
    raise GitCloneError('Failed to open cloned repo') from e


def clone_with_retries(git_url,
                       checkout_dir,
                       git_callbacks=None,
                       branch=None,
                       blobless=False):
  """Clone with retries."""
  logging.info('Cloning %s to %s', git_url, checkout_dir)
  os.makedirs(checkout_dir, exist_ok=True)
  for attempt in range(CLONE_TRIES):
    try:
      repo = clone(git_url, checkout_dir, git_callbacks, blobless=blobless)
      repo.cache = {}
      if branch:
        _checkout_branch(repo, branch)
      return repo
    except GitCloneError as e:
      shutil.rmtree(checkout_dir, ignore_errors=True)
      if attempt == CLONE_TRIES - 1:
        raise GitCloneError('Clone failed after %d attempts' %
                            CLONE_TRIES) from e
      time.sleep(RETRY_SLEEP_SECONDS)
    except NoBranchError as e:
      raise NoBranchError('Branch "%s" not found in repo "%s"' %
                          (branch, git_url)) from e

  return None


def _use_existing_checkout(git_url,
                           checkout_dir,
                           git_callbacks=None,
                           branch=None):
  """Update and use existing checkout."""
  repo = pygit2.Repository(checkout_dir)
  repo.cache = {}
  if repo.remotes['origin'].url != _git_mirror(git_url):
    # The URL in the code is the source of truth,
    # so if the remote URL does not match
    # update to the correct URL.
    logging.warning('origin URL updated:\nOld: %s\nNew: %s',
                    repo.remotes['origin'].url, _git_mirror(git_url))
    repo.remotes.set_url('origin', _git_mirror(git_url))

  if branch:
    try:
      _checkout_branch(repo, branch)
    except NoBranchError as e:
      raise NoBranchError('Branch "%s" not found in repo "%s"' %
                          (branch, git_url)) from e

  reset_repo(repo, git_callbacks)
  logging.info('Using existing checkout at %s', checkout_dir)
  return repo


def ensure_updated_checkout(git_url,
                            checkout_dir,
                            git_callbacks=None,
                            branch=None,
                            blobless=False):
  """Ensure updated checkout."""
  if os.path.exists(checkout_dir):
    # Already exists, reset and checkout latest revision.
    try:
      return _use_existing_checkout(
          git_url, checkout_dir, git_callbacks=git_callbacks, branch=branch)
    except Exception as e:
      # Failed to re-use existing checkout. Delete it and start over.
      err_str = str(e)
      if isinstance(e, subprocess.CalledProcessError):
        # add the git output to the log
        err_str = f'{err_str}\n{e.stderr.decode()}'
      logging.exception('Failed to load existing checkout: %s', err_str)
      shutil.rmtree(checkout_dir)

  repo = clone_with_retries(
      git_url,
      checkout_dir,
      git_callbacks=git_callbacks,
      branch=branch,
      blobless=blobless)
  logging.info('Repo now at: %s', repo.head.peel().message)
  return repo


def reset_repo(repo: pygit2.Repository, git_callbacks, force: bool = False):
  """
  Fetch the latest changes from remote, and set upstream branch correctly.
  This will try to be smart and not refetch repos that recently have been
  fetched.

  Use force to override this
  """
  remote_url = repo.remotes['origin'].url
  key = (remote_url, repo.path)
  now = datetime.datetime.now(datetime.timezone.utc)

  if not force and key in FETCH_CACHE and (
      now - FETCH_CACHE[key]).total_seconds() < FETCH_CACHE_SECONDS:
    logging.info('Skipping fetch for %s, fetched recently.', remote_url)
    repo.reset(repo.head.target, pygit2.enums.ResetMode.HARD)
    return

  logging.info('Fetching for %s', remote_url)
  env = _set_git_callback_env(git_callbacks)

  # Use git cli instead of pygit2 for performance
  subprocess.run(['git', 'fetch', 'origin'],
                 cwd=repo.workdir,
                 env=env,
                 capture_output=True,
                 check=True)
  FETCH_CACHE[key] = now

  # Pygit2 equivalent of above call
  # repo.remotes['origin'].fetch(callbacks=git_callbacks)
  remote_branch = repo.lookup_branch(
      repo.head.name.replace('refs/heads/', 'origin/'),
      pygit2.enums.BranchType.REMOTE)

  # Reset to remote branch.
  repo.head.set_target(remote_branch.target)
  repo.reset(remote_branch.target, pygit2.enums.ResetMode.HARD)
