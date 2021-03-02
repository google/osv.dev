#!/usr/bin/env python3
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
"""Importer sources."""

from google.protobuf import json_format
import os
import pygit2
import time
import yaml

# pylint: disable=relative-beyond-top-level
from . import types
from . import vulnerability_pb2

AUTHOR_EMAIL = 'infra@osv.dev'
PUSH_RETRIES = 2
PUSH_RETRY_SLEEP_SECONDS = 10


class GitRemoteCallback(pygit2.RemoteCallbacks):
  """Authentication callbacks."""

  def __init__(self, username, ssh_key_public_path, ssh_key_private_path):
    super().__init__()
    self._username = username
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path

  def credentials(self, url, username_from_url, allowed_types):
    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_USERNAME:
      return pygit2.Username(self._username)

    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_SSH_KEY:
      return pygit2.Keypair(self._username, self._ssh_key_public_path,
                            self._ssh_key_private_path, '')

    return None


def get_source_repository(source_name):
  """Get source repository."""
  return types.SourceRepository.get_by_id(source_name)


def parse_source_id(source_id):
  """Get the source name and id from source_id."""
  return source_id.split(':', 1)


def repo_path(repo):
  """Return local disk path to repo."""
  # Remove '.git' component.
  return os.path.dirname(repo.path.rstrip(os.sep))


def parse_vulnerability(path):
  """Parse vulnerability YAML."""
  vulnerability = vulnerability_pb2.VulnerabilityNew()
  with open(path) as f:
    data = yaml.safe_load(f)
  json_format.ParseDict(data, vulnerability)

  return vulnerability


def _yaml_str_representer(dumper, data):
  """YAML str representer override."""
  if '\n' in data:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class _YamlDumper(yaml.SafeDumper):
  """Overridden dumper to to use | for multiline strings."""


_YamlDumper.add_representer(str, _yaml_str_representer)


def vulnerability_to_yaml(vulnerability, output_path):
  """Convert Vulnerability to YAML."""
  with open(output_path, 'w') as handle:
    data = json_format.MessageToDict(vulnerability)
    yaml.dump(data, handle, sort_keys=False, Dumper=_YamlDumper)


def vulnerability_has_range(vulnerability, introduced, fixed):
  """Check if a vulnerability has a range."""
  for affected_range in vulnerability.affects.ranges:
    if affected_range.type != vulnerability_pb2.AffectedRangeNew.Type.GIT:
      continue

    if (affected_range.introduced == introduced and
        affected_range.fixed == fixed):
      return True

  return False


def update_vulnerability(vulnerability, repo_url, result):
  """Update vulnerability from AffectedResult."""
  has_updates = False
  # Add any additional discovered ranges.
  for introduced, fixed in result.affected_ranges:
    if not vulnerability_has_range(vulnerability, introduced, fixed):
      has_updates = True
      vulnerability.affects.ranges.add(
          type=vulnerability_pb2.AffectedRangeNew.Type.GIT,
          repo=repo_url,
          introduced=introduced,
          fixed=fixed)

  # Add additional discovered versions.
  for tag in result.tags:
    if tag not in vulnerability.affects.versions:
      has_updates = True
      vulnerability.affects.versions.append(tag)

  return has_updates


def push_source_changes(repo, commit_message, git_callbacks):
  """Push source changes."""
  repo.index.write()
  tree = repo.index.write_tree()
  author = git_author()
  repo.create_commit(repo.head.name, author, author, commit_message, tree,
                     [repo.head.peel().oid])

  for retry_num in range(1 + PUSH_RETRIES):
    try:
      repo.remotes['origin'].push([repo.head.name], callbacks=git_callbacks)
    except pygit2.GitError:
      if retry_num == PUSH_RETRIES:
        return False

      time.sleep(PUSH_RETRY_SLEEP_SECONDS)

      # Try rebasing.
      commit = repo.head.peel()
      repo.remotes['origin'].fetch(callbacks=git_callbacks)
      remote_branch = repo.lookup_branch(
          repo.head.name.replace('refs/heads/', 'origin/'),
          pygit2.GIT_BRANCH_REMOTE)

      # Reset to remote branch.
      repo.head.set_target(remote_branch.target)
      repo.reset(remote_branch.target, pygit2.GIT_RESET_HARD)

      # Then cherrypick our original commit.
      repo.cherrypick(commit.id)
      if repo.index.conflicts is not None:
        # Conflict. Don't try to resolve.
        return False

      # Success, commit and try pushing again.
      tree = repo.index.write_tree()
      repo.create_commit(repo.head.name, commit.author, commit.author,
                         commit.message, tree, [repo.head.peel().oid])
      repo.state_cleanup()

  return True


def git_author():
  """Get the git author for commits."""
  return pygit2.Signature('OSV', AUTHOR_EMAIL)
