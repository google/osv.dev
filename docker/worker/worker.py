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
import datetime
import json
import logging
import os
import re
import redis
import requests
import resource
import shutil
import subprocess
import sys
import threading
import time

import google.cloud.exceptions
from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud import storage

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import osv
import osv.ecosystems
import osv.cache
import osv.logs
from osv import vulnerability_pb2
import oss_fuzz

DEFAULT_WORK_DIR = '/work'
OSS_FUZZ_GIT_URL = 'https://github.com/google/oss-fuzz.git'
TASK_SUBSCRIPTION = 'tasks'
MAX_LEASE_DURATION = 6 * 60 * 60  # 4 hours.
_TIMEOUT_SECONDS = 60

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

_ECOSYSTEM_PUSH_TOPICS = {
    'PyPI': 'pypi-bridge',
}

_state = threading.local()
_state.source_id = None
_state.bug_id = None


class RedisCache(osv.cache.Cache):
  """Redis cache implementation."""

  redis_instance: redis.client.Redis

  def __init__(self, host, port):
    self.redis_instance = redis.Redis(host, port)

  def get(self, key):
    try:
      return json.loads(self.redis_instance.get(json.dumps(key)))
    except Exception:
      # TODO(ochang): Remove this after old cache entries are flushed.
      return None

  def set(self, key, value, ttl):
    return self.redis_instance.set(json.dumps(key), json.dumps(value), ex=ttl)


class UpdateConflictError(Exception):
  """Update conflict exception."""


def _setup_logging_extra_info():
  """Set up extra GCP logging information."""

  old_factory = logging.getLogRecordFactory()

  def record_factory(*args, **kwargs):
    """Insert jsonPayload fields to all logs."""

    record = old_factory(*args, **kwargs)
    if not hasattr(record, 'json_fields'):
      record.json_fields = {}

    if getattr(_state, 'source_id', None):
      record.json_fields['source_id'] = _state.source_id

    if getattr(_state, 'bug_id', None):
      record.json_fields['bug_id'] = _state.bug_id

    record.json_fields['thread'] = record.thread

    return record

  logging.setLogRecordFactory(record_factory)


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

        extension_seconds = int(min(self.EXTENSION_TIME_SECONDS, time_left))

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
      except Exception:
        logging.exception('Leaser thread failed: ')


def clean_artifacts(oss_fuzz_dir):
  """Clean build artifact from previous runs."""
  build_dir = os.path.join(oss_fuzz_dir, 'build')
  if os.path.exists(build_dir):
    shutil.rmtree(build_dir, ignore_errors=True)


def mark_bug_invalid(message):
  """Mark a bug as invalid."""
  source_id = get_source_id(message)
  for bug in osv.Bug.query(osv.Bug.source_id == source_id):
    bug.withdrawn = datetime.datetime.utcnow()
    bug.status = osv.BugStatus.INVALID
    bug.put()

    osv.delete_affected_commits(bug.key.id())


def get_source_id(message):
  """Get message ID."""
  source_id = message.attributes['source_id']
  if source_id:
    return source_id

  testcase_id = message.attributes['testcase_id']
  if testcase_id:
    return oss_fuzz.SOURCE_PREFIX + testcase_id

  return None


def add_fix_information(vulnerability, fix_result):
  """Add fix information to a vulnerability."""
  database_specific = {}
  fix_commit = fix_result.commit
  if ':' in fix_result.commit:
    database_specific['fixed_range'] = fix_result.commit
    fix_commit = fix_result.commit.split(':')[1]

  has_changes = False

  for affected_package in vulnerability.affected:
    added_fix = False

    # Count unique repo URLs.
    repos = set()
    for affected_range in affected_package.ranges:
      if affected_range.type == vulnerability_pb2.Range.GIT:
        repos.add(affected_range.repo)

    for affected_range in affected_package.ranges:
      if affected_range.type != vulnerability_pb2.Range.GIT:
        continue

      # If this range does not include the fixed commit, add it.
      # Do this if:
      #   - There is only one repo URL in the entire vulnerability, or
      #   - The repo URL matches the FixResult repo URL.
      if ((fix_result.repo_url == affected_range.repo or len(repos) == 1) and
          not any(event.fixed == fix_commit
                  for event in affected_range.events)):
        added_fix = True
        has_changes = True
        affected_range.events.add(fixed=fix_commit)
        # Clear existing versions to re-compute them from scratch.
        del affected_package.versions[:]

    if added_fix:
      affected_package.database_specific.update(database_specific)

  return has_changes


# TODO(ochang): Remove this function once GHSA's encoding is fixed.
def fix_invalid_ghsa(vulnerability):
  """Attempt to fix an invalid GHSA entry.

  Args:
    vulnerability: a vulnerability object.

  Returns:
    whether the GHSA entry is valid.
  """
  packages = {}
  for affected in vulnerability.affected:
    details = packages.setdefault(
        (affected.package.ecosystem, affected.package.name), {
            'has_single_introduced': False,
            'has_fixed': False
        })

    has_bad_equals_encoding = False
    for affected_range in affected.ranges:
      if len(
          affected_range.events) == 1 and affected_range.events[0].introduced:
        details['has_single_introduced'] = True
        if (affected.versions and
            affected.versions[0] == affected_range.events[0].introduced):
          # https://github.com/github/advisory-database/issues/59.
          has_bad_equals_encoding = True

      for event in affected_range.events:
        if event.fixed:
          details['has_fixed'] = True

    if has_bad_equals_encoding:
      if len(affected.ranges) == 1:
        # Try to fix this by removing the range.
        del affected.ranges[:]
        logging.info('Removing bad range from %s', vulnerability.id)
      else:
        # Unable to fix this if there are multiple ranges.
        return False

  for details in packages.values():
    # Another case of a bad encoding: Having ranges with a single "introduced"
    # event, when there are actually "fix" events encoded in another range for
    # the same package.
    if details['has_single_introduced'] and details['has_fixed']:
      return False

  return True


def maybe_normalize_package_names(vulnerability):
  """Normalize package names as necessary."""
  for affected in vulnerability.affected:
    if affected.package.ecosystem == 'PyPI':
      # per https://peps.python.org/pep-0503/#normalized-names
      affected.package.name = re.sub(r'[-_.]+', '-',
                                     affected.package.name).lower()

  return vulnerability


def filter_unsupported_ecosystems(vulnerability):
  """Remove unsupported ecosystems from vulnerability."""
  filtered = []
  for affected in vulnerability.affected:
    # CVE-converted OSV records have no package information.
    if not affected.HasField('package'):
      filtered.append(affected)
    elif osv.ecosystems.get(affected.package.ecosystem):
      filtered.append(affected)
    else:
      logging.warning('%s contains unsupported ecosystem "%s"',
                      vulnerability.id, affected.package.ecosystem)
  del vulnerability.affected[:]
  vulnerability.affected.extend(filtered)


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
    logging.info('Created task runner')

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
    deleted = message.attributes['deleted'] == 'true'

    source_repo = osv.get_source_repository(source)
    if source_repo.type == osv.SourceRepositoryType.GIT:
      repo = osv.ensure_updated_checkout(
          source_repo.repo_url,
          os.path.join(self._sources_dir, source),
          git_callbacks=self._git_callbacks(source_repo),
          branch=source_repo.repo_branch)

      vuln_path = os.path.join(osv.repo_path(repo), path)
      if not os.path.exists(vuln_path):
        logging.info('%s was deleted.', vuln_path)
        if deleted:
          self._handle_deleted(source_repo, path)

        return

      if deleted:
        logging.info('Deletion request but source still exists, aborting.')
        return

      try:
        vulnerabilities = osv.parse_vulnerabilities(
            vuln_path, key_path=source_repo.key_path)
      except Exception:
        logging.exception('Failed to parse vulnerability %s:', vuln_path)
        return

      current_sha256 = osv.sha256(vuln_path)
    elif source_repo.type == osv.SourceRepositoryType.BUCKET:
      if deleted:
        self._handle_deleted(source_repo, path)
        return
      storage_client = storage.Client()
      bucket = storage_client.bucket(source_repo.bucket)
      try:
        blob = bucket.blob(path).download_as_bytes()
      except google.cloud.exceptions.NotFound:
        logging.exception('Bucket path %s does not exist.', path)
        return

      current_sha256 = osv.sha256_bytes(blob)
      try:
        vulnerabilities = osv.parse_vulnerabilities_from_data(
            blob,
            extension=os.path.splitext(path)[1],
            key_path=source_repo.key_path)
      except Exception:
        logging.exception('Failed to parse vulnerability %s', path)
        return

      repo = None
    elif source_repo.type == osv.SourceRepositoryType.REST_ENDPOINT:
      vulnerabilities = []
      request = requests.get(source_repo.link + path, timeout=_TIMEOUT_SECONDS)
      if request.status_code != 200:
        logging.error('Failed to fetch REST API: %s', request.status_code)
        return
      vuln = request.json()
      try:
        vulnerabilities.append(osv.parse_vulnerability_from_dict(vuln))
      except Exception as e:
        logging.exception('Failed to parse %s:%s', vuln['id'], e)
      current_sha256 = osv.sha256_bytes(request.text.encode())
      repo = None

    else:
      raise RuntimeError('Unsupported SourceRepository type.')

    if current_sha256 != original_sha256:
      logging.warning(
          'sha256sum of %s no longer matches (expected=%s vs current=%s).',
          path, original_sha256, current_sha256)
      return

    for vulnerability in vulnerabilities:
      self._do_update(source_repo, repo, vulnerability, path, original_sha256)

  def _handle_deleted(self, source_repo, vuln_path):
    """Handle deleted source."""
    vuln_id = os.path.splitext(os.path.basename(vuln_path))[0]
    bug = osv.Bug.get_by_id(vuln_id)
    if not bug:
      logging.error('Failed to find Bug with ID %s', vuln_id)
      return

    bug_source_path = osv.source_path(source_repo, bug)
    if bug_source_path != vuln_path:
      logging.info('Request path %s does not match %s, not marking as invalid.',
                   vuln_path, bug_source_path)
      return

    logging.info('Marking %s as invalid.', vuln_id)
    bug.status = osv.BugStatus.INVALID
    bug.put()

  def _push_new_ranges_and_versions(self, source_repo, repo, vulnerability,
                                    output_path, original_sha256):
    """Pushes new ranges and versions."""
    osv.write_vulnerability(
        vulnerability, output_path, key_path=source_repo.key_path)
    repo.index.add_all()
    return osv.push_source_changes(
        repo,
        f'Update {vulnerability.id}',
        self._git_callbacks(source_repo),
        expected_hashes={
            output_path: original_sha256,
        })

  def _analyze_vulnerability(self, source_repo, repo, vulnerability, path,
                             original_sha256):
    """Analyze vulnerability and push new changes."""
    # Add OSS-Fuzz
    added_fix_info = False
    bug = osv.Bug.get_by_id(vulnerability.id)
    if bug:
      fix_result = osv.FixResult.get_by_id(bug.source_id)
      if fix_result:
        added_fix_info = add_fix_information(vulnerability, fix_result)

    result = osv.analyze(
        vulnerability,
        analyze_git=not source_repo.ignore_git,
        detect_cherrypicks=source_repo.detect_cherrypicks,
        versions_from_repo=source_repo.versions_from_repo)
    if not result.has_changes and not added_fix_info:
      return result

    if not source_repo.editable:
      return result

    output_path = os.path.join(osv.repo_path(repo), path)
    if self._push_new_ranges_and_versions(source_repo, repo, vulnerability,
                                          output_path, original_sha256):
      logging.info('Updated range/versions for vulnerability %s.',
                   vulnerability.id)
      return result

    logging.warning('Discarding changes for %s due to conflicts.',
                    vulnerability.id)
    raise UpdateConflictError

  def _do_update(self, source_repo, repo, vulnerability, relative_path,
                 original_sha256):
    """Process updates on a vulnerability."""
    logging.info('Processing update for vulnerability %s', vulnerability.id)
    vulnerability = maybe_normalize_package_names(vulnerability)
    if source_repo.name == 'ghsa' and not fix_invalid_ghsa(vulnerability):
      logging.warning('%s has an encoding error, skipping.', vulnerability.id)
      return

    filter_unsupported_ecosystems(vulnerability)

    orig_modified_date = vulnerability.modified.ToDatetime()
    try:
      result = self._analyze_vulnerability(source_repo, repo, vulnerability,
                                           relative_path, original_sha256)
    except UpdateConflictError:
      # Discard changes due to conflict.
      return

    # Update datastore with new information.
    bug = osv.Bug.get_by_id(vulnerability.id)
    if not bug:
      if source_repo.name == 'oss-fuzz':
        logging.warning('%s not found for OSS-Fuzz source.', vulnerability.id)
        return

      bug = osv.Bug(
          db_id=vulnerability.id,
          timestamp=osv.utcnow(),
          status=osv.BugStatus.PROCESSED,
          source_of_truth=osv.SourceOfTruth.SOURCE_REPO)

    bug.update_from_vulnerability(vulnerability)
    bug.public = True
    bug.import_last_modified = orig_modified_date
    # OSS-Fuzz sourced bugs use a different format for source_id.
    if source_repo.name != 'oss-fuzz' or not bug.source_id:
      bug.source_id = f'{source_repo.name}:{relative_path}'

    if bug.withdrawn:
      bug.status = osv.BugStatus.INVALID
    else:
      bug.status = osv.BugStatus.PROCESSED

    if not vulnerability.affected:
      logging.info('%s does not affect any packages. Marking as invalid.',
                   vulnerability.id)
      bug.status = osv.BugStatus.INVALID
    bug.put()

    osv.update_affected_commits(bug.key.id(), result.commits, bug.public)
    self._notify_ecosystem_bridge(vulnerability)

  def _notify_ecosystem_bridge(self, vulnerability):
    """Notify ecosystem bridges."""
    ecosystems = set()
    for affected in vulnerability.affected:
      if affected.package.ecosystem in ecosystems:
        continue

      ecosystems.add(affected.package.ecosystem)
      ecosystem_push_topic = _ECOSYSTEM_PUSH_TOPICS.get(
          affected.package.ecosystem)
      if ecosystem_push_topic:
        publisher = pubsub_v1.PublisherClient()
        cloud_project = os.environ['GOOGLE_CLOUD_PROJECT']
        push_topic = publisher.topic_path(cloud_project, ecosystem_push_topic)
        publisher.publish(
            push_topic,
            data=json.dumps(osv.vulnerability_to_dict(vulnerability)).encode())

  def _do_process_task(self, subscriber, subscription, ack_id, message,
                       done_event):
    """Process task with timeout."""
    try:
      with self._ndb_client.context():
        source_id = get_source_id(message) or message.attributes.get(
            'source', None)
        _state.source_id = source_id
        _state.bug_id = message.attributes.get('allocated_bug_id', None)

        task_type = message.attributes['type']
        if task_type in ('regressed', 'fixed'):
          oss_fuzz.process_bisect_task(self._oss_fuzz_dir, task_type, source_id,
                                       message)
        elif task_type == 'impact':
          try:
            oss_fuzz.process_impact_task(source_id, message)
          except osv.ImpactError:
            logging.exception('Failed to process impact: ')
        elif task_type == 'invalid':
          mark_bug_invalid(message)
        elif task_type == 'update':
          self._source_update(message)

        _state.source_id = None
        subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
    except Exception:
      logging.exception('Unexpected exception while processing task: ',)
      subscriber.modify_ack_deadline(
          subscription=subscription, ack_ids=[ack_id], ack_deadline_seconds=0)
    finally:
      logging.info('Ending task')
      done_event.set()

  def handle_timeout(self, subscriber, subscription, ack_id, message):
    """Handle a timeout."""
    subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
    task_type = message.attributes['type']
    source_id = get_source_id(message) or message.attributes.get('source', None)

    logging.warning('Task %s timed out (source_id=%s)', task_type, source_id)
    if task_type in ('fixed', 'regressed'):
      oss_fuzz.handle_timeout(task_type, source_id, self._oss_fuzz_dir, message)

  def _log_task_latency(self, message):
    """Determine how long ago the task was requested.

    Log how long it took to be serviced."""
    request_time = message.attributes.get('req_timestamp')
    if request_time:
      request_time = int(request_time)
      latency = int(time.time()) - request_time
      task_type = message.attributes['type']
      source_id = get_source_id(message) or message.attributes.get(
          'source', None)

      logging.info('Task %s (source_id=%s) latency %d', task_type, source_id,
                   latency)

  def loop(self):
    """Task loop."""
    subscriber = pubsub_v1.SubscriberClient()

    cloud_project = os.environ['GOOGLE_CLOUD_PROJECT']
    subscription = subscriber.subscription_path(cloud_project,
                                                TASK_SUBSCRIPTION)

    def process_task(ack_id, message):
      """Process a task."""
      osv.ensure_updated_checkout(OSS_FUZZ_GIT_URL, self._oss_fuzz_dir)
      clean_artifacts(self._oss_fuzz_dir)

      # Enforce timeout by doing the work in another thread.
      done_event = threading.Event()
      thread = threading.Thread(
          target=self._do_process_task,
          args=(subscriber, subscription, ack_id, message, done_event),
          daemon=True)
      logging.info('Creating task thread for %s', message)
      thread.start()

      done = done_event.wait(timeout=MAX_LEASE_DURATION)
      logging.info('Returned from task thread')
      self._log_task_latency(message)
      if not done:
        self.handle_timeout(subscriber, subscription, ack_id, message)
        logging.warning('Timed out processing task')

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
  parser = argparse.ArgumentParser(description='Worker')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument('--ssh_key_public', help='Public SSH key path')
  parser.add_argument('--ssh_key_private', help='Private SSH key path')
  parser.add_argument(
      '--redis_host', help='URL to redis instance, enables redis cache')
  parser.add_argument(
      '--redis_port', default=6379, help='Port of redis instance')
  args = parser.parse_args()

  if args.redis_host:
    osv.ecosystems.config.set_cache(
        RedisCache(args.redis_host, args.redis_port))

  osv.ecosystems.config.work_dir = args.work_dir

  # Work around kernel bug: https://gvisor.dev/issue/1765
  resource.setrlimit(resource.RLIMIT_MEMLOCK,
                     (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

  subprocess.call(('service', 'docker', 'start'))

  oss_fuzz_dir = os.path.join(args.work_dir, 'oss-fuzz')

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  # Temp files are on the persistent local SSD,
  # and they do not get removed when GKE sends a SIGTERM to stop the pod.
  # Manually clear the tmp_dir folder of any leftover files
  # TODO(michaelkedar): use an ephemeral disk for temp storage.
  if os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  # Add oss-fuzz/infra to the import path so we can import from it.
  sys.path.append(os.path.join(oss_fuzz_dir, 'infra'))

  # Suppress OSS-Fuzz build error logs. These are expected as part of
  # bisection.
  logging.getLogger('helper').setLevel(logging.CRITICAL)

  osv.ensure_updated_checkout(OSS_FUZZ_GIT_URL, oss_fuzz_dir)

  ndb_client = ndb.Client()
  with ndb_client.context():
    task_runner = TaskRunner(ndb_client, oss_fuzz_dir, args.work_dir,
                             args.ssh_key_public, args.ssh_key_private)
    task_runner.loop()


if __name__ == '__main__':
  osv.logs.setup_gcp_logging('worker')
  _setup_logging_extra_info()
  main()
