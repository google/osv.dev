# Copyright 2024 Google LLC
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
"""OSS-Fuzz -> OSV feed Syncer."""

import argparse
import json
import logging
import os
import pprint
import re
import tempfile
import urllib.parse
import urllib.request

from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter
from google.cloud import pubsub_v1
from google.cloud import storage
import yaml

import osv
from osv.google_issue_tracker import client
from osv.google_issue_tracker import issue_tracker
import osv.logs

OSS_FUZZ_GIT_URL = 'https://github.com/google/oss-fuzz.git'
DEFAULT_LOOKBACK_DAYS = 14
DEFAULT_COMPONENT_ID = '1638179'

_QUERY = ('modified>today-{lookback_days} type:vulnerability '
          '-title:"build failure" componentid:{component_id}')

_SEVERITY_MAP = {
    0: 'Critical',
    1: 'High',
    2: 'Medium',
    3: 'Low',
    4: 'Missing',
}


class Syncer:
  """OSS-Fuzz -> OSV Syncer.

  OSS-Fuzz issues are partially bisected by ClusterFuzz. The granularity of the
  bisection depends on how frequent builds in OSS-Fuzz happen.

  OSV needs the exact commit that both introduces and fixes a vulnerability, so
  we need to do a finer-grained bisect starting from the revisions that
  ClusterFuzz has.
  """

  def __init__(self,
               oss_fuzz_dir: str | None = None,
               dry_run: bool = True,
               lookback_days: int = DEFAULT_LOOKBACK_DAYS,
               component_id: str = DEFAULT_COMPONENT_ID,
               osv_project: str | None = None,
               clusterfuzz_project: str | None = None):
    self.osv_project = osv_project or os.environ.get('GOOGLE_CLOUD_PROJECT',
                                                     'oss-vdb')
    self.clusterfuzz_project = (
        clusterfuzz_project or
        os.environ.get('CLUSTERFUZZ_PROJECT', 'clusterfuzz-external'))
    self.tasks_topic = f'projects/{self.osv_project}/topics/tasks'

    self.osv_db = datastore.Client(project=self.osv_project)
    self.oss_fuzz_db = datastore.Client(project=self.clusterfuzz_project)
    self.osv_publisher = pubsub_v1.PublisherClient()
    self.storage = storage.Client.create_anonymous_client()

    self.oss_fuzz_dir = oss_fuzz_dir or os.path.join(tempfile.gettempdir(),
                                                     'oss-fuzz')
    self.dry_run = dry_run
    self.lookback_days = lookback_days
    self.component_id = component_id

  def ensure_oss_fuzz_checkout(self):
    """Ensures OSS-Fuzz repository is checked out shallowly."""
    if not os.path.exists(self.oss_fuzz_dir) or not os.path.exists(
        os.path.join(self.oss_fuzz_dir, 'projects')):
      logging.info('Cloning OSS-Fuzz shallowly to %s', self.oss_fuzz_dir)
      osv.ensure_updated_checkout(OSS_FUZZ_GIT_URL, self.oss_fuzz_dir, depth=1)

  def process_issue(self, issue: dict):
    """Process an OSS-Fuzz issue."""
    issue_id = issue['issueId']
    if is_wontfix(issue):
      logging.info('%s is wontfix', issue_id)
      testcase = self.get_oss_fuzz_testcase(issue_id)
      if testcase:
        testcase_id = str(testcase.key.id)
        self.send_osv_request({
            'type': 'invalid',
            'source_id': f'oss-fuzz:{testcase_id}',
            'testcase_id': testcase_id,
        })
      return

    cf_testcase = self.get_oss_fuzz_testcase(issue_id)
    if not cf_testcase:
      logging.warning('No testcase found for issue %s', issue_id)
      return

    testcase_id = str(cf_testcase.key.id)
    if not self.has_analyzed_regression(testcase_id):
      logging.info('%s has not analyzed regression', testcase_id)
      self.send_bisection_request(cf_testcase, 'regressed')

    if is_fixed(issue) and not self.has_analyzed_fixed(testcase_id):
      logging.info('%s is fixed but has not analyzed fixed', testcase_id)
      self.send_bisection_request(cf_testcase, 'fixed')

  def sync(self):
    """Runs the sync."""
    self.ensure_oss_fuzz_checkout()

    tracker = issue_tracker.IssueTracker(client.build())
    counter = 0

    query = _QUERY.format(
        lookback_days=self.lookback_days, component_id=self.component_id)
    logging.info('Finding issues with query: %s', query)

    for issue in tracker.find_issues(query):
      counter += 1
      if counter % 10 == 0:
        logging.info('Processed %d issues', counter)

      try:
        self.process_issue(issue)
      except Exception:
        logging.error(
            'Failed to process issue %s', issue['issueId'], exc_info=True)

    logging.info('Sync complete. Processed total of %d issues.', counter)

  def send_bisection_request(self, cf_testcase: datastore.Entity,
                             bisect_type: str):
    """Sends bisection request to OSV."""
    if bisect_type == 'regressed':
      commit_range = cf_testcase.get('regression')
    else:
      assert bisect_type == 'fixed'
      commit_range = cf_testcase.get('fixed')

    main_repo = get_main_repo(self.oss_fuzz_dir, cf_testcase['project_name'])
    try:
      # Map the ClusterFuzz-bisected build revision numbers into commit hashes
      # as starting points for OSV's bisection infra.
      old_commit, new_commit = get_commits(cf_testcase, main_repo, commit_range)
    except ValueError:
      logging.info(
          'Failed to extract bisected commit range. Deriving this instead.')
      # Create a best effort starting range for bisection.
      old_commit, new_commit = self.derive_commit_range(cf_testcase,
                                                        bisect_type, main_repo)

    fuzz_target = ''
    if cf_testcase.get('additional_metadata'):
      fuzz_target = json.loads(cf_testcase['additional_metadata']).get(
          'fuzzer_binary_name', '')

    testcase_id = str(cf_testcase.key.id)
    request = {
        'type':
            bisect_type,
        'source_id':
            f'oss-fuzz:{testcase_id}',
        'testcase_id':
            testcase_id,
        'project_name':
            cf_testcase['project_name'],
        'architecture':
            cf_testcase.get('architecture', 'x86_64'),
        'sanitizer':
            get_sanitizer_name(cf_testcase['job_type']),
        'fuzz_target':
            fuzz_target,
        'old_commit':
            old_commit,
        'new_commit':
            new_commit,
        'issue_id':
            str(cf_testcase.get('bug_information', '')),
        'crash_type':
            cf_testcase.get('crash_type', ''),
        'crash_state':
            cf_testcase.get('crash_state', ''),
        'security':
            str(cf_testcase.get('security_flag', '')),
        'severity':
            _SEVERITY_MAP.get(cf_testcase.get('security_severity'), 'Missing')
            if cf_testcase.get('security_severity') is not None else '',
        'timestamp':
            cf_testcase['timestamp'].isoformat()
            if cf_testcase.get('timestamp') else '',
        'repo_url':
            main_repo,
    }

    self.send_osv_request(request)

  def send_osv_request(self, request: dict):
    """Sends a request to OSV."""
    logging.info('Sending request: %s', pprint.pformat(request, indent=2))
    if not self.dry_run:
      self.osv_publisher.publish(self.tasks_topic, b'', **request)

  def get_oss_fuzz_testcase(self, issue_id: str) -> datastore.Entity | None:
    """Gets an OSS-Fuzz testcase entity from an issue ID."""
    query = self.oss_fuzz_db.query(kind='Testcase')
    query = query.add_filter(
        filter=PropertyFilter('bug_information', '=', str(issue_id)))
    testcase = next(query.fetch(limit=1), None)
    return testcase

  def has_analyzed_regression(self, testcase_id: str) -> bool:
    key = self.osv_db.key('RegressResult', f'oss-fuzz:{testcase_id}')
    return bool(self.osv_db.get(key))

  def has_analyzed_fixed(self, testcase_id: str) -> bool:
    key = self.osv_db.key('FixResult', f'oss-fuzz:{testcase_id}')
    return bool(self.osv_db.get(key))

  def derive_commit_range(self, cf_testcase: datastore.Entity, bisect_type: str,
                          main_repo: str) -> tuple[str, str]:
    """Derives a best effort commit range in absense of a valid
    ClusterFuzz-bisected revision range."""
    url_format = get_revisions_url_format(cf_testcase)

    # Get the very first and very last revision available.
    first_revision, last_revision = self.get_first_and_last_revision(
        cf_testcase)

    # Map them to commit hashes.
    first_commit = get_commit(
        url_format.format(revision=first_revision), main_repo)
    last_commit = get_commit(
        url_format.format(revision=last_revision), main_repo)
    crash_commit = get_commit(
        url_format.format(revision=cf_testcase['crash_revision']), main_repo)

    if bisect_type == 'regressed':
      # If we are bisecting for the commit that introduced, the starting
      # range is (earliest build revision, crashing revision)
      return first_commit, crash_commit

    assert bisect_type == 'fixed'
    # If we are bisecting for the commit that fixed, the starting
    # range is (crashing revision, latest available build revision)
    return crash_commit, last_commit

  def get_first_and_last_revision(self, cf_testcase: datastore.Entity):
    """Gets the last and first revision number of the build for a testcase."""
    build_url = json.loads(cf_testcase['additional_metadata'])['build_url']
    # Turn the build URL into a regex that matches any revision number.
    build_url_pattern = re.sub(r'(\d+)\.zip$', r'(\\d+).zip', build_url)

    _, netloc, path, _, _ = urllib.parse.urlsplit(build_url_pattern)
    bucket = self.storage.get_bucket(netloc)
    directory, pattern = path.rsplit('/', maxsplit=1)

    first_revision = None
    last_revision = None

    blob_names = [
        blob.name for blob in bucket.list_blobs(
            prefix=directory.lstrip('/') + '/', delimiter='/')
    ]
    blob_names.sort()
    for blob in blob_names:
      match = re.match(pattern, os.path.basename(blob))
      if match:
        if first_revision is None:
          first_revision = match.group(1)

        last_revision = match.group(1)

    return first_revision, last_revision


def is_wontfix(issue: dict) -> bool:
  return issue.get('issueState', {}).get('status') in ('NOT_REPRODUCIBLE',
                                                       'INTENDED_BEHAVIOUR',
                                                       'OBSOLETE', 'INFEASIBLE')


def is_fixed(issue: dict) -> bool:
  return issue.get('issueState', {}).get('status') in ('FIXED', 'VERIFIED')


def get_sanitizer_name(job_type: str) -> str:
  """Gets the sanitizer name from a ClusterFuzz job type."""
  if '_asan' in job_type:
    return 'address'

  if '_msan' in job_type:
    return 'memory'

  if '_ubsan' in job_type:
    return 'undefined'

  raise ValueError(f'unknown sanitizer from job type: {job_type}')


def get_revisions_url_format(cf_testcase: datastore.Entity) -> str:
  """Gets a format string for retrieving git commit information from an OSS-Fuzz
  revision number."""
  build_url = json.loads(cf_testcase['additional_metadata'])['build_url']
  build_url = build_url.replace('gs://', 'https://storage.googleapis.com/')
  return re.sub(r'(\d+)\.zip$', '{revision}.srcmap.json', build_url)


def get_commits(cf_testcase: datastore.Entity, main_repo: str,
                commit_range: str | None) -> tuple[str, str]:
  """Gets the commit hashes corresponding to an OSS-Fuzz ClusterFuzz commit
  range."""
  if not commit_range or commit_range == 'NA':
    raise ValueError(f'Invalid commit range "{commit_range}"')

  start_revision, end_revision = commit_range.split(':')

  url_format = get_revisions_url_format(cf_testcase)
  old_commit_srcmap_url = url_format.format(revision=start_revision)
  new_commit_srcmap_url = url_format.format(revision=end_revision)

  old_commit = get_commit(old_commit_srcmap_url, main_repo)
  new_commit = get_commit(new_commit_srcmap_url, main_repo)

  if old_commit == new_commit:
    # This indicates an infrastructure issue.
    raise ValueError('old_commit is equal to new_commit')

  return old_commit, new_commit


def get_commit(srcmap_url: str, main_repo: str) -> str:
  """Gets the relevant commit hash from an OSS-Fuzz srcmap."""
  with urllib.request.urlopen(srcmap_url) as f:
    srcmap = json.load(f)

  def normalize_url(url: str) -> str:
    return url.rstrip('/').removesuffix('.git')

  for entry in srcmap.values():
    if normalize_url(entry['url']) == normalize_url(main_repo):
      return entry['rev']

  raise ValueError(f'main repo {main_repo} not found in srcmap {srcmap_url}')


def get_main_repo(oss_fuzz_dir: str, project_name: str) -> str:
  """Gets the main repo for a given OSS-Fuzz project."""
  project_yaml_path = os.path.join(oss_fuzz_dir, 'projects', project_name,
                                   'project.yaml')
  with open(project_yaml_path, 'r', encoding='utf-8') as f:
    project = yaml.safe_load(f)

  return project['main_repo']


def main():
  parser = argparse.ArgumentParser(description='OSS-Fuzz -> OSV feed Syncer')
  parser.add_argument(
      '--oss-fuzz-dir',
      type=str,
      default=os.environ.get('OSS_FUZZ_DIR', '/work/oss-fuzz'),
      help='Path to OSS-Fuzz checkout.')
  parser.add_argument(
      '--dry-run',
      action=argparse.BooleanOptionalAction,
      default=True,
      help='Perform dry run without publishing Pub/Sub tasks.')
  parser.add_argument(
      '--lookback-days',
      type=int,
      default=DEFAULT_LOOKBACK_DAYS,
      help='Number of lookback days when querying issues.')
  parser.add_argument(
      '--component-id',
      type=str,
      default=DEFAULT_COMPONENT_ID,
      help='Google Issue Tracker component ID.')

  args = parser.parse_args()

  osv.logs.setup_gcp_logging('oss_fuzz_syncer')

  syncer = Syncer(
      oss_fuzz_dir=args.oss_fuzz_dir,
      dry_run=args.dry_run,
      lookback_days=args.lookback_days,
      component_id=args.component_id)
  syncer.sync()


if __name__ == '__main__':
  main()
