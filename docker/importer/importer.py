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
"""OSV Importer."""
import argparse
import logging
import os
import tempfile

from google.cloud import ndb
from google.protobuf import json_format
import pygit2
import yaml

import osv

DEFAULT_WORK_DIR = '/work'


class SourceRepository(ndb.Model):
  """Source repository."""
  # The name of the source.
  name = ndb.StringProperty()
  # The repo URL for the source.
  repo_url = ndb.StringProperty()
  # The username to use for SSH auth.
  repo_username = ndb.StringProperty()
  # The directory in the repo where Vulnerability data is stored.
  directory_path = ndb.StringProperty()


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


class Importer:
  """Importer."""

  def __init__(self, ssh_key_public_path, ssh_key_private_path):
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path

  def run(self):
    """Run importer."""
    # Currently only importing OSS-Fuzz data.
    oss_fuzz_source = ndb.Key(SourceRepository, 'oss-fuzz').get()
    if not oss_fuzz_source:
      raise RuntimeError('OSS-Fuzz source not found.')

    self.process_oss_fuzz(oss_fuzz_source)

  def process_oss_fuzz(self, oss_fuzz_source):
    """Process OSS-Fuzz source data."""
    # Export OSS-Fuzz Vulnerability data into source repository.
    # OSS-Fuzz data is first imported via a special Pub/Sub pipeline into OSV.
    # This data needs to be dumped into a publicly accessible/editable place for
    # manual/human editing if required.
    #
    # This then becomes the source of truth where any edits are imported back
    # into OSV.
    with tempfile.TemporaryDirectory() as tmp_dir:
      callbacks = GitRemoteCallback(oss_fuzz_source.repo_username,
                                    self._ssh_key_public_path,
                                    self._ssh_key_private_path)
      repo = osv.clone_with_retries(
          oss_fuzz_source.repo_url, tmp_dir, callbacks=callbacks)
      if not repo:
        raise RuntimeError('Failed to clone source repo')

      vulnerabilities_path = os.path.join(tmp_dir,
                                          oss_fuzz_source.directory_path or '')

      # TODO(ochang): Make this more efficient by recording whether or not we
      # imported already in Datastore.
      for bug in osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED):
        if not bug.source_id.startswith(oss_fuzz_source.name):
          continue

        source_id = bug.source_id.split(':')[1]
        project_dir = os.path.join(vulnerabilities_path, bug.project)
        os.makedirs(project_dir, exist_ok=True)
        vulnerability_path = os.path.join(project_dir, source_id + '.yaml')

        if os.path.exists(vulnerability_path):
          continue

        with open(vulnerability_path, 'w') as handle:
          data = json_format.MessageToDict(bug.to_vulnerability())
          yaml.safe_dump(data, handle, sort_keys=False)

      # Commit changes.
      repo.index.add_all()
      repo.index.write()
      tree = repo.index.write_tree()
      author = _git_author()
      print(repo.head.name)
      repo.create_commit(repo.head.name, author, author, 'Import from OSS-Fuzz',
                         tree, [repo.head.peel().oid])

      # TODO(ochang): Rebase and retry if necessary.
      repo.remotes['origin'].push([repo.head.name], callbacks=callbacks)

    # TODO(ochang): Import user/manual changes made in the repo and create new
    # analysis tasks.


def _git_author():
  """Get the git author for commits."""
  return pygit2.Signature('OSV', 'infra@osv.dev')


def _yaml_str_representer(dumper, data):
  """YAML str representer override."""
  if '\n' in data:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data)


def main():
  logging.getLogger().setLevel(logging.INFO)
  logging.getLogger('google.api_core.bidi').setLevel(logging.ERROR)
  logging.getLogger('google.cloud.pubsub_v1.subscriber._protocol.'
                    'streaming_pull_manager').setLevel(logging.ERROR)

  parser = argparse.ArgumentParser(description='Importer')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument('--ssh_key_public', help='Public SSH key path')
  parser.add_argument('--ssh_key_private', help='Private SSH key path')
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  # Override YAML string printing to use | for multiline strings.
  yaml.add_representer(str, _yaml_str_representer, Dumper=yaml.SafeDumper)
  importer = Importer(args.ssh_key_public, args.ssh_key_private)
  importer.run()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  with _ndb_client.context():
    main()
