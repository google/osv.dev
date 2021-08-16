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
import logging
import os
import subprocess
import tempfile
import time
import traceback

from google.cloud import ndb
import pygit2

from . import ecosystems
from . import repos
from . import models
from . import vulnerability_pb2

TAG_PREFIX = 'refs/tags/'

AffectedResult = collections.namedtuple('AffectedResult',
                                        'tags commits affected_ranges')

AnalyzeResult = collections.namedtuple('AnalyzeResult', 'has_changes commits')

TagsInfo = collections.namedtuple('TagsInfo', 'tags latest_tag')

_DATASTORE_BATCH_SIZE = 10000
_DATASTORE_BATCH_SLEEP = 5


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

  def get_affected(self, repo, regress_commits, fix_commits):
    """"Get list of affected tags and commits for a bug given regressed and
    fixed commits."""
    affected_commits, affected_ranges, tags = self._get_affected_range(
        repo, regress_commits, fix_commits)

    return AffectedResult(tags, affected_commits, affected_ranges)

  def _get_affected_range(self, repo, regress_commits, fix_commits):
    """Get affected range."""
    range_collector = RangeCollector()
    commits = set()
    seen_commits = set()
    tags = set()
    commits_to_tags = _get_commit_to_tag_mappings(repo)

    branches = []
    if self.detect_cherrypicks:
      # Check all branches for cherry picked regress/fix commits (sorted for
      # determinism).
      branches = sorted(repo.branches.remote)
    else:
      if fix_commits:
        # If not detecting cherry picks, take only branches that contain the fix
        # commit. Otherwise we may have false positives.
        for fix_commit in fix_commits:
          branches.extend(_branches_with_commit(repo, fix_commit))
      elif regress_commits:
        # If only a regress commit is available, we need to find all branches
        # that it reaches.
        for regress_commit in regress_commits:
          branches.extend(_branches_with_commit(repo, regress_commit))

    for branch in branches:
      ref = 'refs/remotes/' + branch

      # Get the earliest equivalent commit in the regression range.
      equivalent_regress_commit = None
      for regress_commit in regress_commits:
        logging.info('Finding equivalent regress commit to %s in %s',
                     regress_commit, ref)
        equivalent_regress_commit = self._get_equivalent_commit(
            repo,
            ref,
            regress_commit,
            detect_cherrypicks=self.detect_cherrypicks)
        if equivalent_regress_commit:
          break

      # If regress_commits is provided, then we should find an equivalent.
      if not equivalent_regress_commit and regress_commits:
        continue

      # Get the latest equivalent commit in the fix range.
      equivalent_fix_commit = None
      for fix_commit in fix_commits:
        logging.info('Finding equivalent fix commit to %s in %s', fix_commit,
                     ref)
        equivalent_fix_commit = self._get_equivalent_commit(
            repo, ref, fix_commit, detect_cherrypicks=self.detect_cherrypicks)
        if equivalent_fix_commit:
          break

      range_collector.add(equivalent_regress_commit, equivalent_fix_commit)

      if equivalent_fix_commit:
        end_commit = equivalent_fix_commit
        include_end = False
      else:
        # Not fixed in this branch. Everything is still vulnerabile.
        end_commit = str(repo.revparse_single(ref).id)
        include_end = True

      if (equivalent_regress_commit, end_commit) in seen_commits:
        continue

      seen_commits.add((equivalent_regress_commit, end_commit))
      cur_commits, cur_tags = get_commit_and_tag_list(
          repo,
          equivalent_regress_commit,
          end_commit,
          commits_to_tags=commits_to_tags,
          include_start=True,
          include_end=include_end)
      commits.update(cur_commits)
      tags.update(cur_tags)

    return commits, range_collector.ranges(), tags

  def _get_equivalent_commit(self,
                             repo,
                             to_search,
                             target_commit,
                             detect_cherrypicks=True):
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

      if not detect_cherrypicks:
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


def _get_commit_to_tag_mappings(repo):
  """Get all commit to tag mappings"""
  mappings = {}
  for ref_name in repo.references:
    if not ref_name.startswith(TAG_PREFIX):
      continue

    ref = repo.references[ref_name]
    mappings.setdefault(str(ref.resolve().peel().id),
                        []).append(ref_name[len(TAG_PREFIX):])

  return mappings


def get_commit_and_tag_list(repo,
                            start_commit,
                            end_commit,
                            commits_to_tags=None,
                            include_start=False,
                            include_end=True):
  """Given a commit range, return the list of commits and tags in the range."""
  logging.info('Getting commits %s..%s', start_commit, end_commit)
  try:
    walker = repo.walk(end_commit,
                       pygit2.GIT_SORT_TOPOLOGICAL | pygit2.GIT_SORT_REVERSE)
  except KeyError as e:
    raise ImpactError('Invalid commit.') from e

  if start_commit:
    walker.hide(start_commit)

  commits = []
  tags = []

  def process_commit(commit):
    commits.append(commit)
    if not commits_to_tags:
      return

    tags.extend(commits_to_tags.get(commit, []))

  for commit in walker:
    if not include_end and str(commit.id) == end_commit:
      continue

    process_commit(str(commit.id))

  if include_start and start_commit:
    process_commit(start_commit)

  return commits, tags


def _branches_with_commit(repo, commit):
  """Get all remote branches that include a commit."""
  # pygit2's implementation of this is much slower, so we use `git`.
  branches = subprocess.check_output(
      ['git', '-C', repo.path, 'branch', '-r', '--contains',
       commit]).decode().splitlines()

  def process_ref(ref):
    return ref.strip().split()[0]

  # Ignore duplicate <remote>/HEAD branch.
  return [process_ref(branch) for branch in branches if '/HEAD' not in branch]


def _batcher(entries, batch_size):
  """Batcher."""
  for i in range(0, len(entries), batch_size):
    yield entries[i:i + batch_size], i + batch_size >= len(entries)


def _throttled_put(to_put):
  """Throttled ndb put."""
  for batch, is_last in _batcher(to_put, _DATASTORE_BATCH_SIZE):
    ndb.put_multi(batch)
    if not is_last:
      time.sleep(_DATASTORE_BATCH_SLEEP)


def _throttled_delete(to_delete):
  """Throttled ndb delete."""
  for batch, is_last in _batcher(to_delete, _DATASTORE_BATCH_SIZE):
    ndb.delete_multi(batch)
    if not is_last:
      time.sleep(_DATASTORE_BATCH_SLEEP)


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

  _throttled_put(to_put)
  _throttled_delete(to_delete)


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


def _analyze_git_ranges(repo_analyzer, checkout_path, vulnerability,
                        range_collectors, new_versions, commits):
  """Analyze git ranges."""
  package_repo_dir = tempfile.TemporaryDirectory()
  package_repo = None

  try:
    grouped_git_ranges = {}
    for affected_range in vulnerability.affects.ranges:
      if affected_range.type != vulnerability_pb2.AffectedRange.GIT:
        continue

      # Convert empty values ('') to None.
      introduced = affected_range.introduced or None
      fixed = affected_range.fixed or None
      range_collectors[affected_range.repo].add(introduced, fixed)

      grouped_git_ranges.setdefault(affected_range.repo, []).append(
          (introduced, fixed))

    for repo_url, affected_ranges in grouped_git_ranges.items():
      if checkout_path:
        repo_name = os.path.basename(repo_url.rstrip('/')).rstrip('.git')
        package_repo = repos.ensure_updated_checkout(
            repo_url, os.path.join(checkout_path, repo_name))
      else:
        package_repo_dir.cleanup()
        package_repo_dir = tempfile.TemporaryDirectory()
        package_repo = repos.clone_with_retries(repo_url, package_repo_dir.name)

      all_introduced = []
      all_fixed = []
      for (introduced, fixed) in affected_ranges:
        if introduced:
          all_introduced.append(introduced)

        if fixed:
          all_fixed.append(fixed)

      try:
        result = repo_analyzer.get_affected(package_repo, all_introduced,
                                            all_fixed)
      except ImpactError:
        logging.warning('Got error while analyzing git range: %s',
                        traceback.format_exc())
        continue

      for introduced, fixed in result.affected_ranges:
        range_collectors[repo_url].add(introduced, fixed)

      new_versions.update(result.tags)
      commits.update(result.commits)
  finally:
    package_repo_dir.cleanup()

  return range_collectors, new_versions, commits


def analyze(vulnerability,
            analyze_git=True,
            checkout_path=None,
            detect_cherrypicks=True,
            versions_from_repo=True):
  """Update and analyze a vulnerability based on its input ranges."""
  # Repo -> Git range collectors
  range_collectors = collections.defaultdict(RangeCollector)
  new_versions = set()
  commits = set()

  # Analyze git ranges.
  if analyze_git:
    repo_analyzer = RepoAnalyzer(detect_cherrypicks=detect_cherrypicks)
    _analyze_git_ranges(repo_analyzer, checkout_path, vulnerability,
                        range_collectors, new_versions, commits)

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
    versions.extend(new_versions)

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
