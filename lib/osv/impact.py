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
"""Impact analysis."""

import collections
import datetime
import logging
import os
import subprocess
import tempfile

from google.cloud import ndb
import pygit2

from . import ecosystems
from . import repos
from . import models
from . import vulnerability_pb2

COMMIT_RANGE_LIMIT = 4

TAG_PREFIX = 'refs/tags/'

# Used in cases where an earlier commit in a regression range cannot be
# determined.
UNKNOWN_COMMIT = 'unknown'

AffectedResult = collections.namedtuple(
    'AffectedResult', 'tags_with_bug tags_with_fix commits affected_ranges '
    'regress_commits fix_commits')

AnalyzeResult = collections.namedtuple('AnalyzeResult', 'has_changes commits')

TagsInfo = collections.namedtuple('TagsInfo', 'tags latest_tag')


class ImpactError(Exception):
  """Impact error."""


class RangeCollector:
  """Affected range collector (preserves insertion order)."""

  def __init__(self):
    self.grouped_ranges = {}

  def add(self, introduced_in, fixed_in):
    """Add a new commit range."""
    if introduced_in in self.grouped_ranges:
      if fixed_in is None:
        # New range doesn't add anything new.
        return

      # Remove in-place as we need to preserve insertion order.
      ranges = self.grouped_ranges[introduced_in]
      ranges.append((introduced_in, fixed_in))
      for value in ranges.copy():
        if value[1] is None:
          ranges.remove(value)
    else:
      self.grouped_ranges[introduced_in] = [(introduced_in, fixed_in)]

  def ranges(self):
    """Return a set representing the collected commit ranges."""
    ranges = []
    for grouped_range in self.grouped_ranges.values():
      for commit_range in grouped_range:
        if commit_range not in ranges:
          ranges.append(commit_range)

    return ranges


class RepoAnalyzer:
  """Repository analyzer."""

  def __init__(self, detect_cherrypicks=True):
    self.detect_cherrypicks = detect_cherrypicks

  def get_affected(self, repo, regress_commit_or_range, fix_commit_or_range):
    """"Get list of affected tags and commits for a bug given regressed and
    fixed commits."""
    # If multiple, assume any commit in the regression range cause the
    # regression.
    regress_commits = get_commit_range(repo, regress_commit_or_range)
    if len(regress_commits) > COMMIT_RANGE_LIMIT:
      raise ImpactError('Too many commits in regression range.')

    # If multiple, assume all commits are necessary for fixing the regression.
    fix_commits = get_commit_range(repo, fix_commit_or_range)
    if len(fix_commits) > COMMIT_RANGE_LIMIT:
      logging.warning('Too many commits in fix range.')
      # Rather than bail out here and potentially leaving a Bug as "unfixed"
      # indefinitely, we do the best we can here, by assuming the last
      # COMMIT_RANGE_LIMIT commits fix the bug.
      fix_commits = fix_commits[-COMMIT_RANGE_LIMIT:]

    # Special case: unknown status for earlier revisions.
    unknown_earlier_revisions = UNKNOWN_COMMIT in regress_commit_or_range

    tags_with_bug = set()
    for commit in regress_commits:
      tags_with_bug.update(self.get_tags_with_commits(repo, [commit]))

    if not regress_commits:
      # If no introduced commit provided, assume all commits prior to fix are
      # vulnerable.
      tags_with_bug.update(get_all_tags(repo))

    tags_with_fix = self.get_tags_with_commits(repo, fix_commits)
    affected_commits, affected_ranges = self.get_affected_range(
        repo, regress_commits, fix_commits)

    if len(regress_commits) > 1 or len(fix_commits) > 1:
      # Don't return ranges if input regressed and fixed commits are not single
      # commits.
      affected_ranges = []

    if unknown_earlier_revisions:
      # Include the unknown marker in resulting entities.
      regress_commits.insert(0, UNKNOWN_COMMIT)

    return AffectedResult(tags_with_bug, tags_with_fix, affected_commits,
                          affected_ranges, regress_commits, fix_commits)

  def get_affected_range(self, repo, regress_commits, fix_commits):
    """Get affected range."""
    range_collector = RangeCollector()
    commits = set()
    seen_commits = set()

    if self.detect_cherrypicks:
      # Check all branches for cherry picked regress/fix commits (sorted for
      # determinism).
      branches = sorted(repo.branches.remote)
    else:
      branches = [repo.head.name.replace('refs/heads/', 'origin/')]

    for branch in branches:
      ref = 'refs/remotes/' + branch

      # Get the earliest equivalent commit in the regression range.
      equivalent_regress_commit = None
      if self.detect_cherrypicks:
        for regress_commit in regress_commits:
          logging.info('Finding equivalent regress commit to %s in %s',
                       regress_commit, ref)
          equivalent_regress_commit = self.get_equivalent_commit(
              repo, ref, regress_commit)
          if equivalent_regress_commit:
            break
      else:
        if regress_commits:
          equivalent_regress_commit = regress_commits[0]

      # If regress_commits is provided, then we should find an equivalent.
      if not equivalent_regress_commit and regress_commits:
        continue

      # Get the latest equivalent commit in the fix range.
      equivalent_fix_commit = None
      if self.detect_cherrypicks:
        for fix_commit in fix_commits:
          logging.info('Finding equivalent fix commit to %s in %s', fix_commit,
                       ref)
          equivalent_commit = self.get_equivalent_commit(repo, ref, fix_commit)
          if equivalent_commit:
            equivalent_fix_commit = equivalent_commit
      else:
        if fix_commits:
          equivalent_fix_commit = fix_commits[-1]

      range_collector.add(equivalent_regress_commit, equivalent_fix_commit)

      last_affected_commits = []
      if equivalent_fix_commit:
        # Last affected commit is the one before the fix.
        last_affected_commits.extend(
            parent.id
            for parent in repo.revparse_single(equivalent_fix_commit).parents)
      else:
        # Not fixed in this branch. Everything is still vulnerabile.
        last_affected_commits.append(repo.revparse_single(ref).id)

      if equivalent_regress_commit:
        commits.add(equivalent_regress_commit)

      for last_affected_commit in last_affected_commits:
        if (equivalent_regress_commit, last_affected_commit) in seen_commits:
          continue

        seen_commits.add((equivalent_regress_commit, last_affected_commit))
        commits.update(
            get_commit_list(repo, equivalent_regress_commit,
                            last_affected_commit))

    return commits, range_collector.ranges()

  def get_equivalent_commit(self, repo, to_search, target_commit):
    """Find an equivalent commit at to_search, or None. The equivalent commit
    can be equal to target_commit."""
    if not target_commit:
      return None

    target = repo.revparse_single(target_commit)
    target_patch_id = repo.diff(target.parents[0], target).patchid

    search = repo.revparse_single(to_search)
    try:
      commits = repo.walk(search.id)
    except ValueError:
      # Invalid commit
      return None

    for commit in commits:
      if commit.id == target.id:
        return target_commit

      if not self.detect_cherrypicks:
        continue

      # Ignore commits without parents and merge commits with multiple parents.
      if not commit.parents or len(commit.parents) > 1:
        continue

      patch_id = repo.cache.get(commit.id)
      if not patch_id:
        diff = repo.diff(commit.parents[0], commit)
        patch_id = diff.patchid
        repo.cache[commit.id] = patch_id

      if patch_id == target_patch_id:
        return str(commit.id)

    # TODO(ochang): Possibly look at commit message, author etc.
    return None

  def get_tags_with_commits(self, repo, commits):
    """Get tags with a given commit."""
    if not commits:
      return set()

    logging.info('Getting tags which contain %s', ','.join(commits))

    tags = [
        ref for ref in repo.listall_references() if ref.startswith(TAG_PREFIX)
    ]

    if self.detect_cherrypicks:
      affected = set()
      for tag in tags:
        if all(
            self.get_equivalent_commit(repo, tag, commit)
            for commit in commits):
          affected.add(tag[len(TAG_PREFIX):])
    else:
      affected = None
      # pygit2 does not provide any easy to way to compute this efficiently, so
      # we use git here.
      for commit in commits:
        current = subprocess.check_output(
            ['git', '-C', repo.path, 'tag', '--contains',
             commit]).decode().splitlines()
        if affected is None:
          affected = set(current)
        else:
          affected &= set(current)

    return affected


def get_commit_range(repo, commit_or_range):
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

  return get_commit_list(repo, start_commit, end_commit)


def get_all_tags(repo):
  """Get all tags."""
  return [
      ref[len(TAG_PREFIX):]
      for ref in repo.listall_references()
      if ref.startswith(TAG_PREFIX)
  ]


def get_commit_list(repo, start_commit, end_commit):
  """Get commit list."""
  logging.info('Getting commits %s..%s', start_commit, end_commit)
  try:
    walker = repo.walk(end_commit,
                       pygit2.GIT_SORT_TOPOLOGICAL | pygit2.GIT_SORT_REVERSE)
  except KeyError as e:
    raise ImpactError('Invalid commit.') from e

  if start_commit:
    walker.hide(start_commit)

  return [str(commit.id) for commit in walker]


def find_latest_tag(repo, tags):
  """Find the latest tag (by commit time)."""
  latest_commit_time = None
  latest_tag = None

  for tag in tags:
    commit = repo.lookup_reference(tag).peel()
    commit_time = (
        datetime.datetime.fromtimestamp(commit.commit_time) -
        datetime.timedelta(minutes=commit.commit_time_offset))
    if not latest_commit_time or commit_time > latest_commit_time:
      latest_commit_time = commit_time
      latest_tag = tag[len(TAG_PREFIX):]

  return latest_tag


def get_tags(repo_url):
  """Get tags information."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    repo = repos.clone_with_retries(repo_url, tmp_dir)
    tags = [
        ref for ref in repo.listall_references() if ref.startswith(TAG_PREFIX)
    ]

    latest_tag = find_latest_tag(repo, tags)
    return TagsInfo([tag[len(TAG_PREFIX):] for tag in tags], latest_tag)


def update_affected_commits(bug_id, commits, project, ecosystem, public):
  """Update affected commits."""
  to_put = []
  to_delete = []

  for commit in commits:
    affected_commit = models.AffectedCommit(
        id=bug_id + '-' + commit,
        bug_id=bug_id,
        commit=commit,
        project=project,
        ecosystem=ecosystem,
        public=public)

    to_put.append(affected_commit)

  # Delete any affected commits that no longer apply. This can happen in cases
  # where a FixResult comes in later and we had previously marked a commit prior
  # to the fix commit as being affected by a vulnerability.
  for existing in models.AffectedCommit.query(
      models.AffectedCommit.bug_id == bug_id):
    if existing.commit not in commits:
      to_delete.append(existing.key)

  ndb.put_multi(to_put)
  ndb.delete_multi(to_delete)


def enumerate_versions(package, ecosystem, affected_ranges):
  """Enumerate versions from SEMVER and ECOSYSTEM input ranges."""
  versions = set()
  for affected_range in affected_ranges:
    if affected_range.type in (vulnerability_pb2.AffectedRange.ECOSYSTEM,
                               vulnerability_pb2.AffectedRange.SEMVER):
      if not affected_range.introduced and not affected_range.fixed:
        continue

      current_versions = ecosystem.enumerate_versions(package,
                                                      affected_range.introduced,
                                                      affected_range.fixed)
      if current_versions:
        versions.update(current_versions)

  versions = list(versions)
  ecosystem.sort_versions(versions)
  return versions


def analyze(vulnerability,
            analyze_git=True,
            checkout_path=None,
            detect_cherrypicks=True,
            versions_from_repo=True):
  """Update and analyze a vulnerability based on its input ranges."""
  package_repo_dir = tempfile.TemporaryDirectory()
  package_repo_url = None
  package_repo = None

  # Repo -> Git range collectors
  range_collectors = collections.defaultdict(RangeCollector)
  versions_with_bug = set()
  versions_with_fix = set()
  commits = set()

  repo_analyzer = RepoAnalyzer(detect_cherrypicks=detect_cherrypicks)
  try:
    for affected_range in vulnerability.affects.ranges:
      if (affected_range.type != vulnerability_pb2.AffectedRange.GIT or
          not analyze_git):
        continue

      # Convert empty values ('') to None.
      introduced = affected_range.introduced or None
      fixed = affected_range.fixed or None
      range_collectors[affected_range.repo].add(introduced, fixed)

    for affected_range in vulnerability.affects.ranges:
      # Go through existing provided ranges to find additional ranges (via
      # cherrypicks and branches).
      if (affected_range.type != vulnerability_pb2.AffectedRange.GIT or
          not analyze_git):
        continue

      current_repo_url = affected_range.repo
      if checkout_path:
        repo_name = os.path.basename(
            current_repo_url.rstrip('/')).rstrip('.git')
        package_repo = repos.ensure_updated_checkout(
            current_repo_url, os.path.join(checkout_path, repo_name))
      else:
        if current_repo_url != package_repo_url:
          # Different repo from previous one.
          package_repo_dir.cleanup()
          package_repo_dir = tempfile.TemporaryDirectory()
          package_repo_url = current_repo_url
          package_repo = repos.clone_with_retries(package_repo_url,
                                                  package_repo_dir.name)

      result = repo_analyzer.get_affected(package_repo,
                                          affected_range.introduced,
                                          affected_range.fixed)
      for introduced, fixed in result.affected_ranges:
        range_collectors[current_repo_url].add(introduced, fixed)

      versions_with_fix.update(result.tags_with_fix)
      versions_with_bug.update(result.tags_with_bug)
      commits.update(result.commits)
  finally:
    package_repo_dir.cleanup()

  # Enumerate ECOSYSTEM and SEMVER ranges.
  ecosystem_helpers = ecosystems.get(vulnerability.package.ecosystem)
  if ecosystem_helpers:
    versions = enumerate_versions(vulnerability.package.name, ecosystem_helpers,
                                  vulnerability.affects.ranges)
  else:
    logging.warning('No ecosystem helpers implemented for %s',
                    vulnerability.package.ecosystem)
    versions = []

  # Add additional versions derived from commits and tags.
  if versions_from_repo:
    versions.extend(versions_with_bug - versions_with_fix)

  # Apply changes.
  has_changes = False
  for repo_url, range_collector in range_collectors.items():
    for introduced, fixed in range_collector.ranges():
      if any(
          # Range collectors use None, while the proto uses '' for empty
          # values.
          (affected_range.introduced or None) == introduced and
          (affected_range.fixed or None) == fixed
          for affected_range in vulnerability.affects.ranges):
        # Range already exists.
        continue

      has_changes = True
      vulnerability.affects.ranges.add(
          type=vulnerability_pb2.AffectedRange.Type.GIT,
          repo=repo_url,
          introduced=introduced,
          fixed=fixed)

  for version in sorted(versions):
    if version not in vulnerability.affects.versions:
      has_changes = True
      vulnerability.affects.versions.append(version)

  if not has_changes:
    return AnalyzeResult(False, commits)

  vulnerability.modified.FromDatetime(models.utcnow())
  return AnalyzeResult(True, commits)
