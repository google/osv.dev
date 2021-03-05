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
"""OSV Worker."""
import argparse
import json
import logging
import os
import math
import resource
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import traceback

from google.cloud import ndb
from google.cloud import pubsub_v1
import pygit2

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import osv
from osv import vulnerability_pb2
import oss_fuzz

DEFAULT_WORK_DIR = '/work'
OSS_FUZZ_GIT_URL = 'https://github.com/google/oss-fuzz.git'
TASK_SUBSCRIPTION = 'tasks'
MAX_LEASE_DURATION = 6 * 60 * 60  # 4 hours.

# Large projects which take way too long to build.
# TODO(ochang): Don't hardcode this.
PROJECT_DENYLIST = {
    'ffmpeg',
    'imagemagick',
    'libreoffice',
}

REPO_DENYLIST = {
    'https://github.com/google/AFL.git',
}

_state = threading.local()


class LogFilter(logging.Filter):
  """Log filter."""

  def filter(self, record):
    """Add metadata to record."""
    source_id = getattr(_state, 'source_id', None)
    if source_id:
      record.extras = {
          'source_id': source_id,
      }

    return True


class GkeLogHandler(logging.StreamHandler):
  """GKE log handler."""

  def format_stackdriver_json(self, record, message):
    """Helper to format a LogRecord in in Stackdriver fluentd format."""
    subsecond, second = math.modf(record.created)

    payload = {
        'message': message,
        'timestamp': {
            'seconds': int(second),
            'nanos': int(subsecond * 1e9)
        },
        'thread': record.thread,
        'severity': record.levelname,
    }

    extras = getattr(record, 'extras', None)
    if extras:
      payload.update(extras)

    return json.dumps(payload)

  def format(self, record):
    """Format the message into JSON expected by fluentd."""
    message = super().format(record)
    return self.format_stackdriver_json(record, message)


class _PubSubLeaserThread(threading.Thread):
  """Thread that continuously renews the lease for a message."""

  EXTENSION_TIME_SECONDS = 10 * 60  # 10 minutes.

  def __init__(self, subscriber_client, subscription, ack_id, done_event,
               max_lease_seconds):
    super().__init__()
    self.daemon = True
    self._subscriber = subscriber_client
    self._subscription = subscription
    self._ack_id = ack_id
    self._done_event = done_event
    self._max_lease_seconds = max_lease_seconds

  def run(self):
    """Run the leaser thread."""
    latest_end_time = time.time() + self._max_lease_seconds

    while True:
      try:
        time_left = latest_end_time - time.time()
        if time_left <= 0:
          logging.warning(
              'Lease reached maximum lease time of %d seconds, '
              'stopping renewal.', self._max_lease_seconds)
          break

        extension_seconds = min(self.EXTENSION_TIME_SECONDS, time_left)

        logging.info('Renewing lease for task by %d seconds.',
                     extension_seconds)
        self._subscriber.modify_ack_deadline(
            subscription=self._subscription,
            ack_ids=[self._ack_id],
            ack_deadline_seconds=extension_seconds)

        # Schedule renewals earlier than the extension to avoid race conditions
        # and performing the next extension too late.
        wait_seconds = min(time_left, self.EXTENSION_TIME_SECONDS // 2)

        # Wait until the next scheduled renewal, or if the task is complete.
        if self._done_event.wait(wait_seconds):
          logging.info('Task complete, stopping renewal.')
          break
      except Exception as e:
        logging.error('Leaser thread failed: %s', str(e))


def ensure_updated_checkout(git_url, checkout_dir):
  """Ensure a Git repo is checked out to the latest master revision."""

  if os.path.exists(checkout_dir):
    repo = pygit2.Repository(checkout_dir)
  else:
    os.makedirs(checkout_dir)
    repo = pygit2.clone_repository(git_url, checkout_dir)

  for remote in repo.remotes:
    remote.fetch()

  repo.reset(repo.head.peel().oid, pygit2.GIT_RESET_HARD)
  repo.checkout('refs/remotes/origin/master')
  logging.info('OSS-Fuzz repo now at: %s', repo.head.peel().message)


def clean_artifacts(oss_fuzz_dir):
  """Clean build artifact from previous runs."""
  build_dir = os.path.join(oss_fuzz_dir, 'build')
  if os.path.exists(build_dir):
    shutil.rmtree(build_dir, ignore_errors=True)


def find_bugs_for_tag(project_name, tag, public):
  """Find bugs for a given project and tag."""
  query = osv.Bug.query(osv.Bug.project == project_name,
                        osv.Bug.affected == tag, osv.Bug.public == public)

  return [bug.key.id() for bug in query]


def process_package_info_task(message):
  """Process project info."""
  package_name = message.attributes['package_name']
  ecosystem = message.attributes['ecosystem']
  repo_url = message.attributes['repo_url']

  tags_info = osv.get_tags(repo_url)
  if tags_info.latest_tag:
    info = osv.PackageInfo(id=f'{ecosystem}/{package_name}')
    info.latest_tag = tags_info.latest_tag
    info.put()

  infos = []
  for tag in tags_info.tags:
    tag_info = osv.PackageTagInfo(id=f'{ecosystem}/{package_name}-{tag}')
    tag_info.package = package_name
    tag_info.ecosystem = ecosystem
    tag_info.tag = tag
    tag_info.bugs = find_bugs_for_tag(package_name, tag, public=True)
    tag_info.bugs_private = find_bugs_for_tag(package_name, tag, public=False)

    infos.append(tag_info)

  ndb.put_multi(infos)


def mark_bug_invalid(message):
  """Mark a bug as invalid."""
  source_id = get_source_id(message)
  bug = osv.Bug.query(osv.Bug.source_id == source_id).get()
  if not bug:
    logging.error('Bug with source id %s does not exist.', source_id)
    return

  bug.status = osv.BugStatus.INVALID
  bug.put()

  affected_commits = osv.AffectedCommit.query(
      osv.AffectedCommit.bug_id == bug.key.id())
  ndb.delete_multi([commit.key for commit in affected_commits])


def get_source_id(message):
  """Get message ID."""
  source_id = message.attributes['source_id']
  if source_id:
    return source_id

  testcase_id = message.attributes['testcase_id']
  if testcase_id:
    return oss_fuzz.SOURCE_PREFIX + testcase_id

  return None


class TaskRunner:
  """Task runner."""

  def __init__(self, ndb_client, oss_fuzz_dir, work_dir, ssh_key_public_path,
               ssh_key_private_path):
    self._ndb_client = ndb_client
    self._oss_fuzz_dir = oss_fuzz_dir
    self._work_dir = work_dir
    self._sources_dir = os.path.join(self._work_dir, 'sources')
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path
    os.makedirs(self._sources_dir, exist_ok=True)

  def _git_callbacks(self, source_repo):
    """Get git auth callbacks."""
    return osv.GitRemoteCallback(source_repo.repo_username,
                                 self._ssh_key_public_path,
                                 self._ssh_key_private_path)

  def _source_update(self, message):
    """Source update."""
    source = message.attributes['source']
    path = message.attributes['path']
    original_sha256 = message.attributes['original_sha256']

    source_repo = osv.get_source_repository(source)
    repo = osv.clone_with_retries(
        source_repo.repo_url,
        os.path.join(self._sources_dir, source),
        callbacks=self._git_callbacks(source_repo))

    yaml_path = os.path.join(osv.repo_path(repo), path)
    current_sha256 = osv.sha256(yaml_path)
    if current_sha256 != original_sha256:
      logging.warning(
          'sha256sum of %s no longer matches (expected=%s vs current=%s).',
          path, original_sha256, current_sha256)
      return

    vulnerability = osv.parse_vulnerability(yaml_path)
    self._do_update(source_repo, repo, vulnerability, yaml_path,
                    original_sha256)

  def _push_new_ranges_and_versions(self, source_repo, repo, vulnerability,
                                    yaml_path, original_sha256, added_ranges,
                                    added_versions):
    """Pushes new ranges and versions."""
    # Add new ranges and versions (sorted for determinism).
    for repo_url, introduced, fixed in sorted(added_ranges):
      vulnerability.affects.ranges.add(
          type=vulnerability_pb2.AffectedRangeNew.Type.GIT,
          repo=repo_url,
          introduced=introduced,
          fixed=fixed)

    for version in sorted(added_versions):
      vulnerability.affects.versions.append(version)

    # Write updates, and push.
    vulnerability.last_modified.FromDatetime(osv.utcnow())
    osv.vulnerability_to_yaml(vulnerability, yaml_path)
    repo.index.add_all()
    return osv.push_source_changes(
        repo,
        f'Update {vulnerability.id}',
        self._git_callbacks(source_repo),
        expected_hashes={
            yaml_path: original_sha256,
        })

  def _do_update(self, source_repo, repo, vulnerability, yaml_path,
                 original_sha256):
    """Process updates on a vulnerability."""
    logging.info('Processing update for vulnerability %s', vulnerability.id)
    package_repo_dir = tempfile.TemporaryDirectory()
    package_repo_url = None
    package_repo = None

    added_ranges = set()
    added_versions = set()
    try:
      for affected_range in vulnerability.affects.ranges:
        # Go through existing provided ranges to find additional ranges (via
        # cherrypicks and branches).
        if affected_range.type != vulnerability_pb2.AffectedRangeNew.GIT:
          continue

        current_repo_url = affected_range.repo
        if current_repo_url != package_repo_url:
          # Different repo from previous one.
          package_repo_dir.cleanup()
          package_repo_dir = tempfile.TemporaryDirectory()
          package_repo_url = current_repo_url
          package_repo = osv.clone_with_retries(package_repo_url,
                                                package_repo_dir.name)

        result = osv.get_affected(package_repo, affected_range.introduced,
                                  affected_range.fixed)
        new_ranges, new_versions = osv.update_vulnerability(
            vulnerability, package_repo_url, result)

        # Collect newly added ranges and versions.
        added_ranges.update(new_ranges)
        added_versions.update(new_versions)
    finally:
      package_repo_dir.cleanup()

    if added_ranges or added_versions:
      if not self._push_new_ranges_and_versions(
          source_repo, repo, vulnerability, yaml_path, original_sha256,
          added_ranges, added_versions):
        logging.warning('Discarding changes for %s due to conflicts.',
                        vulnerability.id)
        return
    else:
      # Nothing to do.
      logging.info('No range/version changes for vulnerability %s.',
                   vulnerability.id)

    # Update datastore with new information.
    bug = osv.Bug.get_by_id(vulnerability.id)
    if not bug:
      # TODO(ochang): Create new entry if needed.
      logging.error('Failed to find bug with ID %s', vulnerability.id)
      return

    bug.update_from_vulnerability(vulnerability)
    bug.put()

  def _do_process_task(self, subscriber, subscription, ack_id, message,
                       done_event):
    """Process task with timeout."""
    try:
      with self._ndb_client.context():
        source_id = get_source_id(message)
        _state.source_id = source_id

        task_type = message.attributes['type']
        if task_type in ('regressed', 'fixed'):
          oss_fuzz.process_bisect_task(self._oss_fuzz_dir, task_type, source_id,
                                       message)
        elif task_type == 'impact':
          try:
            oss_fuzz.process_impact_task(source_id, message)
          except osv.ImpactError:
            logging.error('Failed to process impact: %s',
                          traceback.format_exc())
        elif task_type == 'package_info':
          process_package_info_task(message)
        elif task_type == 'invalid':
          mark_bug_invalid(message)
        elif task_type == 'update':
          self._source_update(message)

        _state.source_id = None
        subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
    except Exception:
      logging.error('Unexpected exception while processing task: %s',
                    traceback.format_exc())
      subscriber.modify_ack_deadline(
          subscription=subscription, ack_ids=[ack_id], ack_deadline_seconds=0)
    finally:
      logging.info('Ending task')
      done_event.set()

  def handle_timeout(self, subscriber, subscription, ack_id, message):
    """Handle a timeout."""
    subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
    task_type = message.attributes['type']
    source_id = get_source_id(message)

    logging.error('Task %s timed out (source_id=%s)', task_type, source_id)
    if task_type in ('fixed', 'regressed'):
      oss_fuzz.handle_timeout(task_type, source_id, self._oss_fuzz_dir, message)

  def loop(self):
    """Task loop."""
    subscriber = pubsub_v1.SubscriberClient()

    cloud_project = os.environ['GOOGLE_CLOUD_PROJECT']
    subscription = subscriber.subscription_path(cloud_project,
                                                TASK_SUBSCRIPTION)

    def process_task(ack_id, message):
      """Process a task."""
      ensure_updated_checkout(OSS_FUZZ_GIT_URL, self._oss_fuzz_dir)
      clean_artifacts(self._oss_fuzz_dir)

      # Enforce timeout by doing the work in another thread.
      done_event = threading.Event()
      thread = threading.Thread(
          target=self._do_process_task,
          args=(subscriber, subscription, ack_id, message, done_event),
          daemon=True)
      thread.start()

      done = done_event.wait(timeout=MAX_LEASE_DURATION)
      logging.info('Returned from task thread')
      if not done:
        self.handle_timeout(subscriber, subscription, ack_id, message)
        logging.error('Timed out processing task')

    while True:
      response = subscriber.pull(subscription=subscription, max_messages=1)
      if not response.received_messages:
        continue

      message = response.received_messages[0].message
      ack_id = response.received_messages[0].ack_id

      leaser_done = threading.Event()
      leaser = _PubSubLeaserThread(subscriber, subscription, ack_id,
                                   leaser_done, MAX_LEASE_DURATION)
      leaser.start()

      try:
        process_task(ack_id, message)
      finally:
        leaser_done.set()
      leaser.join()


def main():
  logging.getLogger().addFilter(LogFilter())
  logging.getLogger().addHandler(GkeLogHandler())
  logging.getLogger().setLevel(logging.INFO)
  logging.getLogger('google.api_core.bidi').setLevel(logging.ERROR)
  logging.getLogger('google.cloud.pubsub_v1.subscriber._protocol.'
                    'streaming_pull_manager').setLevel(logging.ERROR)

  parser = argparse.ArgumentParser(description='Worker')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument('--ssh_key_public', help='Public SSH key path')
  parser.add_argument('--ssh_key_private', help='Private SSH key path')
  args = parser.parse_args()

  # Work around kernel bug: https://gvisor.dev/issue/1765
  resource.setrlimit(resource.RLIMIT_MEMLOCK,
                     (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

  subprocess.call(('service', 'docker', 'start'))

  oss_fuzz_dir = os.path.join(args.work_dir, 'oss-fuzz')

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  # Add oss-fuzz/infra to the import path so we can import from it.
  sys.path.append(os.path.join(oss_fuzz_dir, 'infra'))

  ensure_updated_checkout(OSS_FUZZ_GIT_URL, oss_fuzz_dir)

  ndb_client = ndb.Client()
  with ndb_client.context():
    task_runner = TaskRunner(ndb_client, oss_fuzz_dir, args.work_dir,
                             args.ssh_key_public_path,
                             args.ssh_key_private_path)
    task_runner.loop()


if __name__ == '__main__':
  main()
