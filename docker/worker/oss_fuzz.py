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
"""OSS-Fuzz integration."""
import datetime
import logging
import os
import re
import sys
import traceback
import tempfile
import yaml

from google.cloud import ndb
import pygit2.enums

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import osv

OSS_FUZZ_ISSUE_URL = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='
SOURCE_PREFIX = 'oss-fuzz:'

COMMIT_RANGE_LIMIT = 4

# Used in cases where an earlier commit in a regression range cannot be
# determined.
UNKNOWN_COMMIT = 'unknown'

# Large projects which take way too long to build.
# TODO(ochang): Don't hardcode this.
PROJECT_DENYLIST = {
    'boringssl',  # https://github.com/google/osv.dev/issues/2178
    'ffmpeg',
    'imagemagick',
    'libreoffice',
}

REPO_DENYLIST = {
    'https://github.com/google/AFL.git',
}


def format_commit_range(old_commit, new_commit):
  """Format a commit range."""
  if old_commit == new_commit:
    return old_commit

  return (old_commit or UNKNOWN_COMMIT) + ':' + new_commit


def find_oss_fuzz_fix_via_commit(repo, start_commit, end_commit, source_id,
                                 issue_id):
  """Find fix commit by checking commit messages."""
  if not source_id.startswith(SOURCE_PREFIX):
    return None

  # Walk through start_commit..end_commit
  try:
    walker = repo.walk(end_commit, pygit2.enums.SortMode.TOPOLOGICAL)
  except KeyError:
    logging.warning('Failed to walk repo with invalid commit: %s', end_commit)
    return None

  walker.hide(start_commit)

  testcase_id = source_id.split(':')[1]
  oss_fuzz_pattern = re.compile(r'oss-?fuzz', re.IGNORECASE)
  has_oss_fuzz_in_message = []
  has_testcase_id_in_message = []
  has_issue_id_in_message = []

  # Look for commits with (in order of decreasing priority):
  # - "oss-?fuzz" and the issue ID in the message.
  # - ClusterFuzz testcase ID in the message.
  # - "oss-?fuzz" in the message.

  for commit in walker:
    commit_message = commit.message.lower()
    has_oss_fuzz = False

    if oss_fuzz_pattern.search(commit_message):
      has_oss_fuzz = True
      has_oss_fuzz_in_message.append(commit)

    if testcase_id in commit_message:
      has_testcase_id_in_message.append(commit)

    if issue_id and issue_id in commit_message and has_oss_fuzz:
      has_issue_id_in_message.append(commit)

  if has_issue_id_in_message:
    return str(has_issue_id_in_message[0].id)

  if has_testcase_id_in_message:
    return str(has_testcase_id_in_message[0].id)

  if len(has_oss_fuzz_in_message) == 1:
    # Only pick the commit if there is a single one that mentions oss-fuzz.
    return str(has_oss_fuzz_in_message[0].id)

  return None


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
      logging.warning('Bisect failed with exception:\n%s',
                      traceback.format_exc())
      return bisector.Result(e.repo_url, None)
    except Exception:
      logging.error('Bisect failed with unexpected exception:\n%s',
                    traceback.format_exc())
      return None

    if result.commit == old_commit:
      logging.warning('Bisect failed for testcase %s, bisected to old_commit',
                      source_id)
      result = None

    return result


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

  if result and result.repo_url in REPO_DENYLIST:
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


def set_bug_attributes(bug, regress_result, fix_result):
  """Set bug attributes from bisection results."""
  issue_id = fix_result.issue_id or regress_result.issue_id
  project = fix_result.project or regress_result.project
  ecosystem = fix_result.ecosystem or regress_result.ecosystem
  summary = fix_result.summary or regress_result.summary
  details = fix_result.details or regress_result.details
  severity = fix_result.severity or regress_result.severity
  reference_urls = fix_result.reference_urls or regress_result.reference_urls

  bug.affected_packages = [
      osv.AffectedPackage(
          package=osv.Package(name=project, ecosystem=ecosystem),
          ecosystem_specific={
              'severity': severity,
          })
  ]

  bug.issue_id = issue_id
  bug.summary = summary
  bug.details = details
  bug.severity = severity
  bug.reference_url_types = {}

  for reference_url in reference_urls:
    if OSS_FUZZ_ISSUE_URL in reference_url:
      link_type = 'REPORT'
    else:
      link_type = 'WEB'
    bug.reference_url_types[reference_url] = link_type

  bug.regressed = regress_result.commit or ''
  bug.fixed = fix_result.commit or ''


def _get_commit_range(repo, commit_or_range):
  """Get a commit range."""
  if not commit_or_range:
    return []

  if ':' not in commit_or_range:
    return [commit_or_range]

  start_commit, end_commit = commit_or_range.split(':')
  if start_commit == UNKNOWN_COMMIT:
    # Special case: No information about earlier builds. Assume the end_commit
    # is the regressing commit as that's the best we can do.
    return [end_commit]

  commits, _ = osv.get_commit_and_tag_list(repo, start_commit, end_commit)
  return commits


def _get_commits(repo, regress_commit_or_range, fix_commit_or_range):
  """Get commits for analysis."""
  regress_commits = _get_commit_range(repo, regress_commit_or_range)
  if len(regress_commits) > COMMIT_RANGE_LIMIT:
    raise osv.ImpactError('Too many commits in regression range.')

  fix_commits = _get_commit_range(repo, fix_commit_or_range)
  if len(fix_commits) > COMMIT_RANGE_LIMIT:
    logging.warning('Too many commits in fix range.')
    # Rather than bail out here and potentially leaving a Bug as "unfixed"
    # indefinitely, we continue.

  return regress_commits, fix_commits


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

  if existing_bug and existing_bug.status == osv.BugStatus.INVALID:
    logging.warning('Bug %s already marked as invalid.', existing_bug.key.id())
    return

  if existing_bug:
    public = existing_bug.public
  else:
    raise osv.ImpactError('Task requested without Bug allocated.')

  repo_url = regress_result.repo_url or fix_result.repo_url
  if not repo_url:
    raise osv.ImpactError('No repo_url set')

  # Always populate Bug attributes, even if the remainder of the analysis fails.
  # This does not mark the Bug as being valid.
  set_bug_attributes(existing_bug, regress_result, fix_result)
  existing_bug.put()

  issue_id = fix_result.issue_id or regress_result.issue_id
  fix_commit = fix_result.commit

  with tempfile.TemporaryDirectory() as tmp_dir:
    repo = osv.clone_with_retries(repo_url, tmp_dir)

    # If not a precise fix commit, try to find the exact one by going through
    # commit messages (oss-fuzz only).
    if source_id.startswith(SOURCE_PREFIX) and ':' in fix_commit:
      start_commit, end_commit = fix_commit.split(':')
      commit = find_oss_fuzz_fix_via_commit(repo, start_commit, end_commit,
                                            source_id, issue_id)
      if commit:
        logging.info('Found exact fix commit %s via commit message (oss-fuzz)',
                     commit)
        fix_commit = commit

    # Actually compute the affected commits/tags.
    repo_analyzer = osv.RepoAnalyzer()
    regress_commits, fix_commits = _get_commits(repo, regress_result.commit,
                                                fix_commit)

    # If multiple, assume the first commit in the regression range cause the
    # regression.
    if regress_commits:
      regress_commit_to_analyze = regress_commits[0]
    else:
      regress_commit_to_analyze = None

    # If multiple, assume the last commit is necessary for fixing the
    # regression.
    if fix_commits:
      fix_commit_to_analyze = fix_commits[-1]
    else:
      fix_commit_to_analyze = None

    result = repo_analyzer.get_affected(repo, [regress_commit_to_analyze],
                                        [fix_commit_to_analyze])
    affected_tags = sorted(list(result.tags))
    logging.info('Found affected %s', ', '.join(affected_tags))

    if len(regress_commits) > 1 or len(fix_commits) > 1:
      # Don't return ranges if input regressed and fixed commits are not single
      # commits.
      result.affected_ranges.clear()

  # If the range resolved to a single commit, simplify it.
  if len(fix_commits) == 1:
    fix_commit = fix_commits[0]
  elif not fix_commits:
    # Not fixed.
    fix_commit = ''

  if (len(regress_commits) == 1 and
      UNKNOWN_COMMIT not in regress_result.commit):
    regress_commit = regress_commits[0]
  else:
    regress_commit = regress_result.commit

  project = fix_result.project or regress_result.project
  ecosystem = fix_result.ecosystem or regress_result.ecosystem
  osv.update_affected_commits(allocated_bug_id, result.commits, public)

  affected_tags = sorted(list(result.tags))
  existing_bug.fixed = fix_commit
  existing_bug.regressed = regress_commit
  existing_bug.status = osv.BugStatus.PROCESSED

  if existing_bug.affected_packages:
    affected_package = existing_bug.affected_packages[0]
  else:
    affected_package = osv.AffectedPackage(
        package=osv.Package(name=project, ecosystem=ecosystem))
    existing_bug.affected_packages = [affected_package]

  affected_package.versions = affected_tags

  # For the AffectedRange, use the first commit in the regress commit range, and
  # the last commit in the fix commit range.
  introduced = regress_commits[0] if regress_commits else ''
  fixed = fix_commits[-1] if fix_commits else ''
  events = [
      osv.AffectedEvent(type='introduced', value=introduced),
  ]
  if fixed:
    events.append(osv.AffectedEvent(type='fixed', value=fixed))

  git_range = osv.AffectedRange2(type='GIT', repo_url=repo_url, events=events)
  affected_package.ranges = [git_range]

  # Expose range data in `database_specific`.
  database_specific = {}
  if ':' in existing_bug.regressed:
    database_specific['introduced_range'] = existing_bug.regressed
  if ':' in existing_bug.fixed:
    database_specific['fixed_range'] = existing_bug.fixed

  if database_specific:
    affected_package.database_specific = database_specific

  # Don't display additional ranges for imprecise commits, as they can be
  # confusing.
  if ':' in existing_bug.fixed or ':' in existing_bug.regressed:
    existing_bug.put()
    return

  def _sort_key(value):
    # Allow sorting of None values.
    return (value[0] or '', value[1] or '', value[2] or '')

  for introduced_in, fixed_in, last_affected_in in sorted(
      result.affected_ranges, key=_sort_key):
    if not fixed_in:
      fixed_in = ''  # convert NoneType to str for next comparison

    if (introduced_in == existing_bug.regressed and
        fixed_in == existing_bug.fixed):
      # Don't repeat the main range.
      continue

    introduced = osv.AffectedEvent(type='introduced', value=introduced_in)
    if introduced not in git_range.events:
      git_range.events.append(introduced)

    if last_affected_in:
      last_affected = osv.AffectedEvent(
          type='last_affected', value=last_affected_in)
      if last_affected not in git_range.events:
        git_range.events.append(last_affected)

    if fixed_in:
      fixed = osv.AffectedEvent(type='fixed', value=fixed_in)
      if fixed not in git_range.events:
        git_range.events.append(fixed)

  existing_bug.put()


def get_ecosystem(oss_fuzz_dir, project_name):
  """Get ecosystem."""
  project_yaml_path = os.path.join(oss_fuzz_dir, 'projects', project_name,
                                   'project.yaml')

  with open(project_yaml_path) as f:
    project_yaml = yaml.safe_load(f)

  language = project_yaml.get('language', '')

  ecosystems = {
      'python': 'PyPI',
      'go': 'Go',
  }

  # C/C++ projects from OSS-Fuzz don't belong to any package ecosystem, so we
  # set "OSS-Fuzz".
  return ecosystems.get(language, 'OSS-Fuzz')


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


def handle_timeout(task_type, source_id, oss_fuzz_dir, message):
  """Handle a timeout."""
  old_commit = message.attributes['old_commit']
  new_commit = message.attributes['new_commit']

  if task_type == 'fixed':
    entity = osv.FixResult(id=source_id)
  else:
    assert task_type == 'regressed'
    entity = osv.RegressResult(id=source_id)

  _set_result_attributes(oss_fuzz_dir, message, entity)

  entity.commit = format_commit_range(old_commit, new_commit)
  entity.error = 'Timeout'
  entity.put()


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
  return details + ('```\n'
                    f'Crash type: {crash_type}\n'
                    f'Crash state:\n{crash_state}'
                    '```\n')
