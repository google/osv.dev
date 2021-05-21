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

import hashlib
import logging
import os
import pygit2
import time
import yaml

from google.protobuf import json_format

# pylint: disable=relative-beyond-top-level
from . import repos
from . import models
from . import vulnerability_pb2

AUTHOR_EMAIL = 'infra@osv.dev'
PUSH_RETRIES = 2
PUSH_RETRY_SLEEP_SECONDS = 10
VULNERABILITY_EXTENSION = '.yaml'


class GitRemoteCallback(pygit2.RemoteCallbacks):
  """Authentication callbacks."""

  def __init__(self, username, ssh_key_public_path, ssh_key_private_path):
    super().__init__()
    self._username = username
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path

  def credentials(self, url, username_from_url, allowed_types):
    logging.info('Allowed types = %s\n', allowed_types)
    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_USERNAME:
      return pygit2.Username(self._username)

    if allowed_types & pygit2.credentials.GIT_CREDENTIAL_SSH_KEY:
      return pygit2.Keypair(self._username, self._ssh_key_public_path,
                            self._ssh_key_private_path, '')

    return None


def get_source_repository(source_name):
  """Get source repository."""
  return models.SourceRepository.get_by_id(source_name)


def parse_source_id(source_id):
  """Get the source name and id from source_id."""
  return source_id.split(':', 1)


def repo_path(repo):
  """Return local disk path to repo."""
  # Remove '.git' component.
  return os.path.dirname(repo.path.rstrip(os.sep))


def parse_vulnerability(path):
  """Parse vulnerability YAML."""
  vulnerability = vulnerability_pb2.Vulnerability()
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


def vulnerability_to_dict(vulnerability):
  """Convert Vulnerability to a dict."""
  return json_format.MessageToDict(vulnerability)


def vulnerability_to_yaml(vulnerability, output_path):
  """Convert Vulnerability to YAML."""
  with open(output_path, 'w') as handle:
    data = vulnerability_to_dict(vulnerability)
    yaml.dump(data, handle, sort_keys=False, Dumper=_YamlDumper)


def vulnerability_has_range(vulnerability, introduced, fixed):
  """Check if a vulnerability has a range."""
  for affected_range in vulnerability.affects.ranges:
    if affected_range.type != vulnerability_pb2.AffectedRange.Type.GIT:
      continue

    if (affected_range.introduced == introduced and
        affected_range.fixed == fixed):
      return True

  return False


def update_vulnerability(vulnerability, repo_url, result):
  """Update vulnerability from AffectedResult."""
  new_ranges = []
  new_versions = []

  # Add any additional discovered ranges.
  for introduced, fixed in result.affected_ranges:
    if not vulnerability_has_range(vulnerability, introduced, fixed):
      new_ranges.append((repo_url, introduced, fixed))

  # Add additional discovered versions.
  for tag in result.tags:
    if tag not in vulnerability.affects.versions:
      new_versions.append(tag)

  return new_ranges, new_versions


def push_source_changes(repo,
                        commit_message,
                        git_callbacks,
                        expected_hashes=None):
  """Push source changes."""
  repo.index.write()
  tree = repo.index.write_tree()
  author = git_author()
  repo.create_commit(repo.head.name, author, author, commit_message, tree,
                     [repo.head.peel().oid])

  for retry_num in range(1 + PUSH_RETRIES):
    try:
      repo.remotes['origin'].push([repo.head.name], callbacks=git_callbacks)
      return True
    except pygit2.GitError as e:
      logging.warning('Failed to push: %s', e)
      if retry_num == PUSH_RETRIES:
        repos.reset_repo(repo, git_callbacks)
        return False

      time.sleep(PUSH_RETRY_SLEEP_SECONDS)

      # Try rebasing.
      commit = repo.head.peel()
      repos.reset_repo(repo, git_callbacks)

      for path, expected_hash in expected_hashes.items():
        current_hash = sha256(path)
        if current_hash != expected_hash:
          logging.warning(
              'Upstream hash for %s changed (expected=%s vs current=%s)', path,
              expected_hash, current_hash)

          continue

      # Then cherrypick our original commit.
      repo.cherrypick(commit.id)
      if repo.index.conflicts is not None:
        # Conflict. Don't try to resolve.
        repo.state_cleanup()
        repos.reset_repo(repo, git_callbacks)
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


def sha256(yaml_path):
  """Computes sha256 sum."""
  hasher = hashlib.sha256()
  with open(yaml_path, 'rb') as f:
    hasher.update(f.read())
  return hasher.hexdigest()


def source_path(source_repo, bug):
  """Get the source path for an osv.Bug."""
  source_name, source_id = parse_source_id(bug.source_id)
  if source_name == 'oss-fuzz':
    path = os.path.join(bug.project, bug.id() + VULNERABILITY_EXTENSION)
    if source_repo.directory_path:
      path = os.path.join(source_repo.directory_path, path)

    return path

  return source_id
