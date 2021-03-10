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
import datetime
import logging
import os
import shutil

from google.cloud import ndb
from google.cloud import pubsub_v1
import pygit2

import osv

DEFAULT_WORK_DIR = '/work'

_BUG_REDO_DAYS = 14
_PROJECT = 'oss-vdb'
_TASKS_TOPIC = 'projects/{project}/topics/{topic}'.format(
    project=_PROJECT, topic='tasks')


def _is_vulnerability_file(file_path):
  """Return whether or not the file is a Vulnerability entry."""
  return file_path.endswith(osv.VULNERABILITY_EXTENSION)


class Importer:
  """Importer."""

  def __init__(self, ssh_key_public_path, ssh_key_private_path, work_dir):
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path
    self._work_dir = work_dir
    self._publisher = pubsub_v1.PublisherClient()

  def _git_callbacks(self, source_repo):
    """Get git auth callbacks."""
    return osv.GitRemoteCallback(source_repo.repo_username,
                                 self._ssh_key_public_path,
                                 self._ssh_key_private_path)

  def _request_analysis(self, bug, source_repo, repo):
    """Request analysis."""
    if bug.source_of_truth == osv.SourceOfTruth.SOURCE_REPO:
      self._request_analysis_external(source_repo, repo, osv.source_path(bug))
    else:
      self._request_internal_analysis(bug)

  def _request_analysis_external(self, source_repo, repo, path):
    """Request analysis."""
    original_sha256 = osv.sha256(os.path.join(osv.repo_path(repo), path))
    self._publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='update',
        source=source_repo.name,
        path=path,
        original_sha256=original_sha256)

  def _request_internal_analysis(self, bug):
    """Request internal analysis."""
    self._publisher.publish(
        _TASKS_TOPIC,
        data=b'',
        type='impact',
        source_id=bug.source_id,
        allocated_id=bug.key.id())

  def run(self):
    """Run importer."""
    # Currently only importing OSS-Fuzz data.
    oss_fuzz_source = osv.get_source_repository('oss-fuzz')
    if not oss_fuzz_source:
      raise RuntimeError('OSS-Fuzz source not found.')

    self.process_oss_fuzz(oss_fuzz_source)
    self.process_updates(oss_fuzz_source)

  def _use_existing_checkout(self, source_repo, checkout_dir):
    """Update and use existing checkout."""
    repo = pygit2.Repository(checkout_dir)
    osv.reset_repo(repo, git_callbacks=self._git_callbacks(source_repo))
    logging.info('Using existing checkout at %s', checkout_dir)
    return repo

  def checkout(self, source_repo):
    """Check out a source repo."""
    checkout_dir = os.path.join(self._work_dir, source_repo.name)

    if os.path.exists(checkout_dir):
      # Already exists, reset and checkout latest revision.
      try:
        return self._use_existing_checkout(source_repo, checkout_dir)
      except Exception as e:
        # Failed to re-use existing checkout. Delete it and start over.
        logging.error('Failed to load existing checkout: %s', e)
        shutil.rmtree(checkout_dir)

    return osv.clone_with_retries(
        source_repo.repo_url,
        checkout_dir,
        callbacks=self._git_callbacks(source_repo))

  def import_new_oss_fuzz_entries(self, repo, oss_fuzz_source):
    """Import new entries."""
    exported = []
    vulnerabilities_path = os.path.join(
        osv.repo_path(repo), oss_fuzz_source.directory_path or '')
    for bug in osv.Bug.query(
        osv.Bug.source_of_truth == osv.SourceOfTruth.INTERNAL):
      if bug.status != osv.BugStatus.PROCESSED:
        continue

      if not bug.public:
        continue

      source_name, _ = osv.parse_source_id(bug.source_id)
      if source_name != oss_fuzz_source.name:
        continue

      vulnerability_path = os.path.join(vulnerabilities_path,
                                        osv.source_path(bug))
      os.makedirs(os.path.dirname(vulnerability_path), exist_ok=True)
      if os.path.exists(vulnerability_path):
        continue

      logging.info('Writing %s', bug.key.id())
      osv.vulnerability_to_yaml(bug.to_vulnerability(), vulnerability_path)
      # The source of truth is now this yaml file.
      bug.source_of_truth = osv.SourceOfTruth.SOURCE_REPO
      exported.append(bug)

    # Commit Vulnerability changes back to the oss-fuzz source repository.
    repo.index.add_all()
    diff = repo.index.diff_to_tree(repo.head.peel().tree)
    if not diff:
      logging.info('No new entries, skipping committing.')
      return

    logging.info('Commiting and pushing new entries')
    if osv.push_source_changes(repo, 'Import from OSS-Fuzz',
                               self._git_callbacks(oss_fuzz_source)):
      ndb.put_multi(exported)

  def schedule_regular_updates(self, repo, source_repo):
    """Schedule regular OSS-Fuzz updates."""
    for bug in osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                             osv.Bug.fixed == ''):
      self._request_analysis(bug, source_repo, repo)

    # Re-compute existing Bugs for a period of time, as upstream changes may
    # affect results.
    cutoff_time = (
        datetime.datetime.utcnow() - datetime.timedelta(days=_BUG_REDO_DAYS))
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.timestamp >= cutoff_time)

    for bug in query:
      logging.info('Re-requesting impact for %s.', bug.key.id())
      if not bug.fixed:
        # Previous query already requested impact tasks for unfixed bugs.
        continue

      self._request_analysis(bug, source_repo, repo)

  def process_updates(self, source_repo):
    """Process user changes and updates."""
    repo = self.checkout(source_repo)

    walker = repo.walk(repo.head.target, pygit2.GIT_SORT_TOPOLOGICAL)
    if source_repo.last_synced_hash:
      walker.hide(source_repo.last_synced_hash)

    # Get list of changed files since last sync.
    changed_entries = set()
    for commit in walker:
      if commit.author.email == osv.AUTHOR_EMAIL:
        continue

      logging.info('Processing commit %s from %s', commit.id,
                   commit.author.email)

      for parent in commit.parents:
        diff = repo.diff(parent, commit)
        for delta in diff.deltas:
          if delta.old_file and _is_vulnerability_file(delta.old_file.path):
            changed_entries.add(delta.old_file.path)

          if delta.new_file and _is_vulnerability_file(delta.new_file.path):
            changed_entries.add(delta.new_file.path)

    # Create tasks for changed files.
    for changed_entry in changed_entries:
      logging.info('Re-analysis triggered for %s', changed_entry)
      self._request_analysis_external(source_repo, repo, changed_entry)

  def process_oss_fuzz(self, oss_fuzz_source):
    """Process OSS-Fuzz source data."""
    # Export OSS-Fuzz Vulnerability data into source repository.
    # OSS-Fuzz data is first imported via a special Pub/Sub pipeline into OSV.
    # This data needs to be dumped into a publicly accessible/editable place for
    # manual/human editing if required.
    #
    # This then becomes the source of truth where any edits are imported back
    # into OSV.
    repo = self.checkout(oss_fuzz_source)
    self.schedule_regular_updates(repo, oss_fuzz_source)
    self.import_new_oss_fuzz_entries(repo, oss_fuzz_source)


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

  importer = Importer(args.ssh_key_public, args.ssh_key_private, args.work_dir)
  importer.run()


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  with _ndb_client.context():
    main()
