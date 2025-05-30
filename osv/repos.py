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

from typing import Any, Dict, Optional

import pygit2
import pygit2.enums
import pygit2.credentials # For pygit2.credentials.Credential

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

  def __init__(self, username: str, ssh_key_public_path: str, ssh_key_private_path: str) -> None:
    super().__init__()
    self.username: str = username
    self.ssh_key_public_path: str = ssh_key_public_path
    self.ssh_key_private_path: str = ssh_key_private_path
    # Add type for `passphrase` if it's used or expected, for now, assume empty string is okay.

  def credentials(self, url: str, username_from_url: Optional[str],
                    allowed_types: pygit2.enums.CredentialType) -> Optional[pygit2.credentials.Credential]:
    """Get credentials."""
    del url # Not used
    del username_from_url # Not used

    if allowed_types & pygit2.enums.CredentialType.USERNAME:
      return pygit2.Username(self.username)

    if allowed_types & pygit2.enums.CredentialType.SSH_KEY: # Corrected enum access
      return pygit2.Keypair(self.username, self.ssh_key_public_path,
                            self.ssh_key_private_path, "") # Assuming empty passphrase

    return None


def _git_mirror(git_url: str) -> str:
  """Get git mirror. If no mirror exists, return the git URL as is."""
  mirror: Optional[str] = _GIT_MIRRORS.get(git_url.rstrip('/'))
  if mirror:
    logging.info('Using mirror %s for git URL %s.', mirror, git_url)
    return mirror

  return git_url


def _checkout_branch(repo: pygit2.Repository, branch: str) -> None:
  """Check out a branch."""
  remote_branch: Optional[pygit2.Branch] = repo.lookup_branch(
      'origin/' + branch, pygit2.enums.BranchType.REMOTE)
  local_branch: Optional[pygit2.Branch] = repo.lookup_branch(
      branch, pygit2.enums.BranchType.LOCAL)

  if not local_branch:
    if remote_branch is None:
      # Consider if NoBranchError should be specific about remote vs local
      raise NoBranchError(f"Remote branch 'origin/{branch}' not found.")
    # Peel to commit object before creating branch
    target_commit: pygit2.Commit = remote_branch.peel(pygit2.Commit)
    local_branch = repo.branches.create(branch, commit=target_commit)

  # Ensure remote_branch is not None before accessing upstream related properties
  if remote_branch is None: # Should have been caught by NoBranchError if local_branch was also None
      raise NoBranchError(f"Remote branch 'origin/{branch}' became None unexpectedly.")

  local_branch.upstream = remote_branch
  local_branch.set_target(remote_branch.target) # target is Oid
  repo.checkout(local_branch)
  repo.reset(remote_branch.target, pygit2.enums.ResetMode.HARD)


def _set_git_callback_env(git_callbacks: Optional[GitRemoteCallback]) -> Dict[str, str]:
  """Set the environment variable to set git callbacks for cli git"""
  env: Dict[str, str] = {
      # Prevent prompting for username if we don't have an ssh key
      'GIT_TERMINAL_PROMPT': '0'
  }
  if git_callbacks:
    # Ensure paths and username are properly quoted/escaped if they can contain spaces or special chars.
    # Python's f-string quoting should handle this for typical paths.
    env['GIT_SSH_COMMAND'] = (
        f'ssh -i "{git_callbacks.ssh_key_private_path}" '
        f'-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null '
        f'-o User="{git_callbacks.username}" -o IdentitiesOnly=yes') # Quoted username
  return env


class GitCloneError(Exception):
  """Git repository clone exception."""


class NoBranchError(Exception):
  """Branch does not exist"""


def clone(git_url: str, checkout_dir: str, git_callbacks: Optional[GitRemoteCallback] = None) -> pygit2.Repository:
  """Perform a clone."""
  try:
    # Use 'git' CLI here as it's much faster than libgit2's clone.
    env: Dict[str, str] = _set_git_callback_env(git_callbacks)

    subprocess.run(
        ['git', 'clone', _git_mirror(git_url), checkout_dir],
        env=env,
        capture_output=True,
        check=True)
    # Assuming checkout_dir is a valid path string for Repository constructor
    return pygit2.Repository(checkout_dir)
  except subprocess.CalledProcessError as e:
    # Include stderr in the exception message for better diagnostics
    raise GitCloneError(f'Failed to clone repo {git_url} to {checkout_dir}:\n{e.stderr.decode()}') from e
  except pygit2.GitError as e:
    raise GitCloneError(f'Failed to open cloned repo at {checkout_dir}') from e


def clone_with_retries(git_url: str, checkout_dir: str,
                       git_callbacks: Optional[GitRemoteCallback] = None,
                       branch: Optional[str] = None) -> pygit2.Repository:
  """Clone with retries."""
  logging.info('Cloning %s to %s', git_url, checkout_dir)
  for attempt in range(CLONE_TRIES):
    try:
      # The `repo.cache = {}` line dynamically adds an attribute.
      # This is okay in Python but can't be formally typed on pygit2.Repository.
      # Consumers of this repo object should be aware of this dynamic attribute.
      repo: pygit2.Repository = clone(git_url, checkout_dir, git_callbacks)
      repo.cache: Dict[Any, Any] = {} # type: ignore[attr-defined]
      if branch:
        _checkout_branch(repo, branch)
      return repo
    except GitCloneError as e:
      shutil.rmtree(checkout_dir, ignore_errors=True)
      if attempt == CLONE_TRIES - 1:
        raise GitCloneError(f'Clone of {git_url} failed after {CLONE_TRIES} attempts') from e
      time.sleep(RETRY_SLEEP_SECONDS)
    except NoBranchError as e: # Specific exception from _checkout_branch
      # Clean up cloned repo if branch checkout fails
      shutil.rmtree(checkout_dir, ignore_errors=True)
      raise NoBranchError(f'Branch "{branch}" not found in repo "{git_url}"') from e

  # This part of the code should be unreachable due to the loop logic.
  # If the loop finishes without returning or raising, it's an issue.
  # Adding an explicit raise to satisfy linters about consistent return.
  raise GitCloneError(f"Clone of {git_url} unexpectedly finished loop without success or specific error.")


def _use_existing_checkout(git_url: str,
                           checkout_dir: str,
                           git_callbacks: Optional[GitRemoteCallback] = None,
                           branch: Optional[str] = None) -> pygit2.Repository:
  """Update and use existing checkout."""
  repo = pygit2.Repository(checkout_dir)
  repo.cache: Dict[Any, Any] = {} # type: ignore[attr-defined]

  # Check if remote URL matches, update if necessary
  origin_remote: pygit2.Remote = repo.remotes['origin']
  mirrored_url = _git_mirror(git_url)
  if origin_remote.url != mirrored_url:
    logging.warning('origin URL updated:\nOld: %s\nNew: %s',
                    origin_remote.url, mirrored_url)
    origin_remote.url = mirrored_url
    # After changing URL, might need to save or re-fetch.
    # For now, assume pygit2 handles this or next fetch will use new URL.

  if branch:
    try:
      _checkout_branch(repo, branch)
    except NoBranchError as e: # Catch specific error
      raise NoBranchError(f'Branch "{branch}" not found in repo "{git_url}" while using existing checkout') from e

  reset_repo(repo, git_callbacks)
  logging.info('Using existing checkout at %s', checkout_dir)
  return repo


def ensure_updated_checkout(git_url: str,
                            checkout_dir: str,
                            git_callbacks: Optional[GitRemoteCallback] = None,
                            branch: Optional[str] = None) -> pygit2.Repository:
  """Ensure updated checkout."""
  if os.path.exists(checkout_dir):
    # Already exists, reset and checkout latest revision.
    try:
      return _use_existing_checkout(
          git_url, checkout_dir, git_callbacks=git_callbacks, branch=branch)
    except Exception as e: # Catch a broader range of exceptions if _use_existing_checkout fails
      # Failed to re-use existing checkout. Delete it and start over.
      err_str = str(e)
      if isinstance(e, subprocess.CalledProcessError):
        # add the git output to the log
        err_str = f'{err_str}\n{e.stderr.decode()}'
      elif isinstance(e, pygit2.GitError):
        err_str = f'pygit2 error: {err_str}'

      logging.warning('Failed to load existing checkout at %s: %s. Re-cloning.', checkout_dir, err_str)
      shutil.rmtree(checkout_dir)

  # If directory didn't exist or was removed, clone fresh.
  repo: pygit2.Repository = clone_with_retries(
      git_url, checkout_dir, git_callbacks=git_callbacks, branch=branch)

  # Log the current commit message after successful clone/update.
  # Peel to commit if head is a reference.
  head_commit: pygit2.Commit = repo.head.peel(pygit2.Commit)
  logging.info('Repo %s now at: %s', git_url, head_commit.message.strip())
  return repo


def reset_repo(repo: pygit2.Repository, git_callbacks: Optional[GitRemoteCallback]) -> None:
  """Reset repo."""
  env: Dict[str, str] = _set_git_callback_env(git_callbacks)
  # Use git cli instead of pygit2 for performance
  try:
    subprocess.run(['git', 'fetch', 'origin'],
                   cwd=repo.workdir, # Ensure cwd is correct
                   env=env,
                   capture_output=True,
                   check=True)
  except subprocess.CalledProcessError as e:
    # Handle fetch failure, e.g., network issue or auth problem not caught by SSH agent
    raise GitCloneError(f"Failed to fetch origin for repo {repo.workdir}: {e.stderr.decode()}") from e

  # Pygit2 equivalent of above call (kept for reference or if direct libgit2 usage is preferred later)
  # repo.remotes['origin'].fetch(callbacks=git_callbacks)

  # Determine the current branch name to find its remote counterpart
  # repo.head.name is like 'refs/heads/main'
  if not repo.head.is_detached:
      current_branch_name = repo.head.shorthand # e.g., 'main'
      remote_branch_name = f'origin/{current_branch_name}'
  else:
      # Handle detached HEAD state - cannot simply derive remote branch.
      # This state might occur if a specific commit was checked out previously.
      # One strategy could be to default to a main branch or raise an error.
      # For now, let's log and potentially raise, as resetting a detached HEAD
      # without a clear branch context can be ambiguous.
      logging.warning(f"Repo at {repo.workdir} is in a detached HEAD state. Reset behavior might be unpredictable.")
      # Attempt to find default branch or handle error
      # This part might need more sophisticated logic depending on desired behavior for detached heads.
      # For now, let's assume we can't proceed if detached and no explicit branch was given to checkout.
      raise NoBranchError("Cannot reset repo in detached HEAD state without explicit branch.")


  remote_branch_obj: Optional[pygit2.Branch] = repo.lookup_branch(
      remote_branch_name, pygit2.enums.BranchType.REMOTE)

  if not remote_branch_obj:
      raise NoBranchError(f"Remote branch '{remote_branch_name}' not found in repo {repo.workdir}.")

  # Reset to remote branch.
  repo.head.set_target(remote_branch_obj.target)
  repo.reset(remote_branch_obj.target, pygit2.enums.ResetMode.HARD)
