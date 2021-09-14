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

import json
import hashlib
import logging
import os
import pygit2
import time
import yaml

from google.protobuf import json_format

# pylint: disable=relative-beyond-top-level
from . import repos
from . import vulnerability_pb2

AUTHOR_EMAIL = 'infra@osv.dev'
PUSH_RETRIES = 2
PUSH_RETRY_SLEEP_SECONDS = 10

YAML_EXTENSIONS = ('.yaml', '.yml')
JSON_EXTENSIONS = ('.json')


def parse_source_id(source_id):
  """Get the source name and id from source_id."""
  return source_id.split(':', 1)


def repo_path(repo):
  """Return local disk path to repo."""
  # Remove '.git' component.
  return os.path.dirname(repo.path.rstrip(os.sep))


def _parse_vulnerability_dict(path):
  """Parse a vulnerability file into a dict."""
  with open(path) as f:
    ext = os.path.splitext(path)[1]
    if ext in YAML_EXTENSIONS:
      return yaml.safe_load(f)

    if ext in JSON_EXTENSIONS:
      return json.load(f)

    raise RuntimeError('Unknown format ' + ext)

  return None


def parse_vulnerability(path, key_path=None):
  """Parse vulnerability YAML."""
  data = _parse_vulnerability_dict(path)
  return parse_vulnerability_from_dict(data, key_path)


def _parse_vulnerabilities(data, key_path):
  """Parse multiple vulnerabilities."""
  if isinstance(data, list):
    return [parse_vulnerability_from_dict(v, key_path) for v in data]

  return [parse_vulnerability_from_dict(data, key_path)]


def parse_vulnerabilities(path, key_path=None):
  """Parse vulnerabilities (potentially multiple in a list)."""
  return _parse_vulnerabilities(_parse_vulnerability_dict(path), key_path)


def parse_vulnerabilities_from_data(data, extension, key_path=None):
  """Parse vulnerabilities from data."""
  if extension in YAML_EXTENSIONS:
    data = yaml.safe_load(data)
  elif extension in JSON_EXTENSIONS:
    data = json.loads(data)
  else:
    raise RuntimeError('Unknown format ' + extension)

  return _parse_vulnerabilities(data, key_path)


def _get_nested_vulnerability(data, key_path=None):
  """Get nested vulnerability."""
  if key_path:
    for component in key_path.split('.'):
      data = data[component]

  return data


def parse_vulnerability_from_dict(data, key_path=None):
  """Parse vulnerability from dict."""
  data = _get_nested_vulnerability(data, key_path)
  vulnerability = vulnerability_pb2.Vulnerability()
  json_format.ParseDict(data, vulnerability, ignore_unknown_fields=True)
  return vulnerability


def _yaml_str_representer(dumper, data):
  """YAML str representer override."""
  if '\n' in data:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class YamlDumper(yaml.SafeDumper):
  """Overridden dumper to to use | for multiline strings."""


YamlDumper.add_representer(str, _yaml_str_representer)


def vulnerability_to_dict(vulnerability):
  """Convert Vulnerability to a dict."""
  result = json_format.MessageToDict(
      vulnerability, preserving_proto_field_name=True)

  if 'affected' not in result:
    return result

  for affected in result['affected']:
    if any(r.get('type') == 'SEMVER' for r in affected.get('ranges', [])):
      return result

  # If no SemVer ranges, output an empty "versions": [] to conform to the spec.
  for affected in result['affected']:
    if 'versions' not in affected:
      affected['versions'] = []

  return result


def _write_vulnerability_dict(data, output_path):
  """Write a vulnerability dict to disk."""
  with open(output_path, 'w') as f:
    ext = os.path.splitext(output_path)[1]
    if ext in YAML_EXTENSIONS:
      yaml.dump(data, f, sort_keys=False, Dumper=YamlDumper)
    elif ext in JSON_EXTENSIONS:
      json.dump(data, f, indent=2)
    else:
      raise RuntimeError('Unknown format ' + ext)


def write_vulnerability(vulnerability, output_path, key_path=None):
  """Update a vulnerability file on disk."""
  if os.path.exists(output_path):
    data = _parse_vulnerability_dict(output_path)
  else:
    # Set up the expected nesting based on key_path.
    data = {}
    if key_path:
      cur = data
      for component in key_path.split('.'):
        cur[component] = {}
        cur = cur[component]

  vuln_data = _get_nested_vulnerability(data, key_path)
  vuln_data.clear()
  vuln_data.update(vulnerability_to_dict(vulnerability))
  _write_vulnerability_dict(data, output_path)


def vulnerability_has_range(vulnerability, introduced, fixed):
  """Check if a vulnerability has a range."""
  for affected_range in vulnerability.affects.ranges:
    if affected_range.type != vulnerability_pb2.AffectedRange.Type.GIT:
      continue

    if (affected_range.introduced == introduced and
        affected_range.fixed == fixed):
      return True

  return False


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


def sha256(file_path):
  """Computes sha256 sum."""
  hasher = hashlib.sha256()
  with open(file_path, 'rb') as f:
    hasher.update(f.read())
  return hasher.hexdigest()


def sha256_bytes(data):
  """Computes sha256sum."""
  hasher = hashlib.sha256()
  hasher.update(data)
  return hasher.hexdigest()


def source_path(source_repo, bug):
  """Get the source path for an osv.Bug."""
  source_name, source_id = parse_source_id(bug.source_id)
  if source_name == 'oss-fuzz':
    path = os.path.join(bug.project[0], bug.id() + source_repo.extension)
    if source_repo.directory_path:
      path = os.path.join(source_repo.directory_path, path)

    return path

  return source_id
