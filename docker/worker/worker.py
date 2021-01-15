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
import math
import resource
import shutil
import subprocess
import sys
import threading
import time
import traceback
import tempfile
import yaml

from google.cloud import ndb
from google.cloud import pubsub_v1
import pygit2

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import osv

DEFAULT_WORK_DIR = '/work'
OSS_FUZZ_GIT_URL = 'https://github.com/google/oss-fuzz.git'
TASK_SUBSCRIPTION = 'tasks'
MAX_LEASE_DURATION = 6 * 60 * 60  # 4 hours.

OSS_FUZZ_ISSUE_URL = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='

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
_ndb_client = ndb.Client()


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


def format_commit_range(old_commit, new_commit):
  """Format a commit range."""
  if old_commit == new_commit:
    return old_commit

  return (old_commit or osv.UNKNOWN_COMMIT) + ':' + new_commit


def do_bisect(bisect_type, source_id, project_name, engine, sanitizer,
              architecture, fuzz_target, old_commit, new_commit, testcase):
  """Do the actual bisect."""
  import bisector
  import build_specified_commit

  with tempfile.NamedTemporaryFile() as f:
    f.write(testcase)
    f.flush()

    build_data = build_specified_commit.BuildData(
        project_name=project_name,
        engine=engine,
        sanitizer=sanitizer,
        architecture=architecture)
    try:
      result = bisector.bisect(bisect_type, old_commit, new_commit, f.name,
                               fuzz_target, build_data)
    except bisector.BisectError as e:
      logging.error('Bisect failed with exception:\n%s', traceback.format_exc())
      return bisector.Result(e.repo_url, None)
    except Exception:
      logging.error('Bisect failed with unexpected exception:\n%s',
                    traceback.format_exc())
      return None

    if result.commit == old_commit:
      logging.error('Bisect failed for testcase %s, bisected to old_commit',
                    source_id)
      result = None

    return result


def get_oss_fuzz_summary(crash_type, crash_state):
  """Generate a summary from OSS-Fuzz crash type and crash state."""
  crash_type = crash_type.splitlines()[0]
  state_lines = crash_state.splitlines()
  if crash_type in ('ASSERT', 'CHECK failure', 'Security CHECK failure',
                    'Security DCHECK failure'):
    return crash_type + ': ' + state_lines[0]

  if crash_type == 'Bad-cast':
    return state_lines[0]

  if not crash_state or crash_state == 'NULL':
    return crash_type

  return crash_type + ' in ' + state_lines[0]


def get_oss_fuzz_details(issue_id, crash_type, crash_state):
  """Generate details from OSS-Fuzz crash type and crash state."""
  details = ''
  if issue_id:
    oss_fuzz_link = OSS_FUZZ_ISSUE_URL + issue_id
    details = f'OSS-Fuzz report: {oss_fuzz_link}\n\n'

  crash_type = crash_type.replace('\n', ' ')
  return details + (f'Crash type: {crash_type}\n'
                    f'Crash state:\n{crash_state}')


def get_ecosystem(oss_fuzz_dir, project_name):
  """Get ecosystem."""
  project_yaml_path = os.path.join(oss_fuzz_dir, 'projects', project_name,
                                   'project.yaml')

  with open(project_yaml_path) as f:
    project_yaml = yaml.safe_load(f)

  language = project_yaml.get('language', '')

  ecosystems = {
      'python': 'pypi',
      'rust': 'cargo',
      'go': 'golang',
  }

  # C/C++ projects from OSS-Fuzz don't belong to any package ecosystem.
  return ecosystems.get(language, '')


def _set_result_attributes(oss_fuzz_dir, message, entity):
  """Set necessary fields from bisection message."""
  project_name = message.attributes['project_name']
  issue_id = message.attributes['issue_id'] or None
  crash_type = message.attributes['crash_type']
  crash_state = message.attributes['crash_state']
  severity = message.attributes['severity'].upper()

  timestamp = message.attributes['timestamp']
  if timestamp:
    timestamp = datetime.datetime.fromisoformat(timestamp)

  entity.project = project_name
  entity.ecosystem = get_ecosystem(oss_fuzz_dir, project_name)
  entity.issue_id = issue_id
  if issue_id:
    entity.reference_urls.append(OSS_FUZZ_ISSUE_URL + issue_id)

  entity.summary = get_oss_fuzz_summary(crash_type, crash_state)
  entity.details = get_oss_fuzz_details(issue_id, crash_type, crash_state)

  if severity:
    entity.severity = severity

  if timestamp:
    entity.timestamp = timestamp


def process_bisect_task(oss_fuzz_dir, bisect_type, source_id, message):
  """Process a bisect task."""
  bisect_type = message.attributes['type']
  project_name = message.attributes['project_name']
  engine = 'libfuzzer'
  architecture = message.attributes['architecture'] or 'x86_64'
  sanitizer = message.attributes['sanitizer']
  fuzz_target = message.attributes['fuzz_target']
  old_commit = message.attributes['old_commit']

  new_commit = message.attributes['new_commit']
  testcase = message.data
  logging.info(
      'Performing %s bisect on source_id=%s, project=%s, engine=%s, '
      'architecture=%s, sanitizer=%s, fuzz_target=%s, old_commit=%s, '
      'new_commit=%s', bisect_type, source_id, project_name, engine,
      architecture, sanitizer, fuzz_target, old_commit, new_commit)

  result = None
  if project_name in PROJECT_DENYLIST:
    logging.info('Skipping bisect for denylisted project %s', project_name)
  elif not old_commit:
    logging.info('Skipping bisect since there is no old_commit.')
  else:
    result = do_bisect(bisect_type, source_id, project_name, engine, sanitizer,
                       architecture, fuzz_target, old_commit, new_commit,
                       testcase)

  if result.repo_url in REPO_DENYLIST:
    logging.info('Skipping because of denylisted repo %s.', result.repo_url)
    return

  if bisect_type == 'fixed':
    entity = osv.FixResult(id=source_id)
  else:
    assert bisect_type == 'regressed'
    entity = osv.RegressResult(id=source_id)

  _set_result_attributes(oss_fuzz_dir, message, entity)

  if result and result.commit:
    logging.info('Bisected to %s', result.commit)
    entity.commit = result.commit
    entity.repo_url = result.repo_url
  else:
    logging.info(
        'Bisect not successfully performed. Setting commit range from request.')
    entity.commit = format_commit_range(old_commit, new_commit)
    entity.repo_url = result.repo_url if result else None
    entity.error = 'Bisect error'

  entity.put()


def update_affected_commits(bug_id, result, project, ecosystem, public):
  """Update affected commits."""
  to_put = []
  to_delete = []

  for commit in result.commits:
    affected_commit = osv.AffectedCommit(
        id=bug_id + '-' + commit,
        bug_id=bug_id,
        commit=commit,
        confidence=result.confidence,
        project=project,
        ecosystem=ecosystem,
        public=public)

    to_put.append(affected_commit)

  # Delete any affected commits that no longer apply. This can happen in cases
  # where a FixResult comes in later and we had previously marked a commit prior
  # to the fix commit as being affected by a vulnerability.
  for existing in osv.AffectedCommit.query(osv.AffectedCommit.bug_id == bug_id):
    if existing.commit not in result.commits:
      to_delete.append(existing.key)

  ndb.put_multi(to_put)
  ndb.delete_multi(to_delete)


def process_impact_task(source_id, message):
  """Process an impact task."""
  logging.info('Processing impact task for %s', source_id)

  regress_result = ndb.Key(osv.RegressResult, source_id).get()
  if not regress_result:
    logging.error('Missing RegressResult for %s', source_id)
    return

  fix_result = ndb.Key(osv.FixResult, source_id).get()
  if not fix_result:
    logging.warning('Missing FixResult for %s', source_id)
    fix_result = osv.FixResult()

  # Check if there is an existing Bug for the same source, but with a different
  # allocated ID. This shouldn't happen.
  allocated_bug_id = message.attributes['allocated_id']

  existing_bug = osv.Bug.query(osv.Bug.source_id == source_id).get()
  if existing_bug and existing_bug.key.id() != allocated_bug_id:
    logging.error('Bug entry already exists for %s with a different ID %s',
                  source_id, existing_bug.key.id())
    return

  if existing_bug:
    public = existing_bug.public
  else:
    raise osv.ImpactError('Task requested without Bug allocated.')

  # TODO(ochang): Handle changing repo types? e.g. SVN -> Git.

  repo_url = regress_result.repo_url or fix_result.repo_url
  if not repo_url:
    raise osv.ImpactError('No repo_url set')

  result = osv.get_affected(repo_url, regress_result.commit, fix_result.commit)
  logging.info('Found affected %s', ', '.join(result.tags))

  # If the range resolved to a single commit, simplify it.
  if len(result.fix_commits) == 1:
    fix_commit = result.fix_commits[0]
  elif not result.fix_commits:
    # Not fixed.
    fix_commit = ''
  else:
    fix_commit = fix_result.commit

  if len(result.regress_commits) == 1:
    regress_commit = result.regress_commits[0]
  else:
    regress_commit = regress_result.commit

  issue_id = fix_result.issue_id or regress_result.issue_id
  project = fix_result.project or regress_result.project
  ecosystem = fix_result.ecosystem or regress_result.ecosystem
  summary = fix_result.summary or regress_result.summary
  details = fix_result.details or regress_result.details
  severity = fix_result.severity or regress_result.severity
  reference_urls = fix_result.reference_urls or regress_result.reference_urls

  update_affected_commits(allocated_bug_id, result, project, ecosystem, public)

  existing_bug.repo_url = repo_url
  existing_bug.fixed = fix_commit
  existing_bug.regressed = regress_commit
  existing_bug.affected = result.tags
  existing_bug.affected_fuzzy = osv.normalize_tags(result.tags)
  existing_bug.confidence = result.confidence
  existing_bug.issue_id = issue_id
  existing_bug.project = project
  existing_bug.ecosystem = ecosystem
  existing_bug.summary = summary
  existing_bug.details = details
  existing_bug.status = osv.BugStatus.PROCESSED
  existing_bug.severity = severity
  existing_bug.reference_urls = reference_urls

  existing_bug.additional_commit_ranges = []
  # Don't display additional ranges for imprecise commits, as they can be
  # confusing.
  if ':' in existing_bug.fixed or ':' in existing_bug.regressed:
    existing_bug.put()
    return

  def _sort_key(value):
    # Allow sorting of None values.
    return (value[0] or '', value[1] or '')

  for introduced_in, fixed_in in sorted(result.affected_ranges, key=_sort_key):
    if (introduced_in == existing_bug.regressed and
        fixed_in == existing_bug.fixed):
      # Don't include the main range.
      continue

    existing_bug.additional_commit_ranges.append(
        osv.CommitRange(introduced_in=introduced_in, fixed_in=fixed_in))

  existing_bug.put()


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


def get_source_id(message):
  """Get message ID."""
  source_id = message.attributes['source_id']
  if source_id:
    return source_id

  testcase_id = message.attributes['testcase_id']
  if testcase_id:
    return 'oss-fuzz:' + testcase_id

  return None


def do_process_task(oss_fuzz_dir, subscriber, subscription, ack_id, message,
                    done_event):
  """Process task with timeout."""
  try:
    with _ndb_client.context():
      source_id = get_source_id(message)
      _state.source_id = source_id

      task_type = message.attributes['type']
      if task_type in ('regressed', 'fixed'):
        process_bisect_task(oss_fuzz_dir, task_type, source_id, message)
      elif task_type == 'impact':
        try:
          process_impact_task(source_id, message)
        except osv.ImpactError:
          logging.error('Failed to process impact: %s', traceback.format_exc())
      elif task_type == 'package_info':
        process_package_info_task(message)

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


def handle_timeout(subscriber, subscription, ack_id, oss_fuzz_dir, message):
  """Handle a timeout."""
  subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])

  bisect_type = message.attributes['type']
  source_id = get_source_id(message)

  logging.error('Task %s timed out (source_id=%s)', bisect_type, source_id)

  if bisect_type not in ('fixed', 'regressed'):
    return

  old_commit = message.attributes['old_commit']
  new_commit = message.attributes['new_commit']

  if bisect_type == 'fixed':
    entity = osv.FixResult(id=source_id)
  else:
    assert bisect_type == 'regressed'
    entity = osv.RegressResult(id=source_id)

  _set_result_attributes(oss_fuzz_dir, message, entity)

  entity.commit = format_commit_range(old_commit, new_commit)
  entity.error = 'Timeout'
  entity.put()


def task_loop(oss_fuzz_dir):
  """Task loop."""

  subscriber = pubsub_v1.SubscriberClient()

  cloud_project = os.environ['GOOGLE_CLOUD_PROJECT']
  subscription = subscriber.subscription_path(cloud_project, TASK_SUBSCRIPTION)

  def process_task(ack_id, message):
    """Process a task."""
    ensure_updated_checkout(OSS_FUZZ_GIT_URL, oss_fuzz_dir)
    clean_artifacts(oss_fuzz_dir)

    # Enforce timeout by doing the work in another thread.
    done_event = threading.Event()
    thread = threading.Thread(
        target=do_process_task,
        args=(oss_fuzz_dir, subscriber, subscription, ack_id, message,
              done_event),
        daemon=True)
    thread.start()

    done = done_event.wait(timeout=MAX_LEASE_DURATION)
    logging.info('Returned from task thread')
    if not done:
      handle_timeout(subscriber, subscription, ack_id, oss_fuzz_dir, message)
      logging.error('Timed out processing task')

  while True:
    response = subscriber.pull(subscription=subscription, max_messages=1)
    if not response.received_messages:
      continue

    message = response.received_messages[0].message
    ack_id = response.received_messages[0].ack_id

    leaser_done = threading.Event()
    leaser = _PubSubLeaserThread(subscriber, subscription, ack_id, leaser_done,
                                 MAX_LEASE_DURATION)
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
  task_loop(oss_fuzz_dir)


if __name__ == '__main__':
  with _ndb_client.context():
    main()
