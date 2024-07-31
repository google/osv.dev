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

import codecs
from dataclasses import dataclass
import logging
import os
import subprocess
import tempfile
import time
import traceback

from google.cloud import ndb
import pygit2
import pygit2.enums

from . import ecosystems
from . import repos
from . import models
from . import vulnerability_pb2

TAG_PREFIX = 'refs/tags/'

# Limit for writing small entities.
_DATASTORE_BATCH_SIZE = 5000
# Limit for writing large entities that are close to the 1MiB max entity size.
# There is additionally a request size limit of 10MiB for batched put()
# requests. We conservatively set this to slightly under (8 as opposed to 10)
# to leave some more breathing room.
_DATASTORE_LARGE_BATCH_SIZE = 8
_DATASTORE_BATCH_SLEEP = 10


@dataclass
class AffectedResult:
  """The tags, commits and affected ranges of a vulnerability."""

  tags: set[str]
  commits: set[str]
  affected_ranges: list[str]


@dataclass
class AnalyzeResult:
  """Capturing if an analysis has any changes and what those changes are."""

  has_changes: bool
  commits: set[str]


@dataclass
class TagsInfo:
  """A repository's tags and the one considered to be the latest version."""

  tags: set[str]
  latest_tag: str


class ImpactError(Exception):
  """Impact error."""


class RangeCollector:
  """Affected range collector (preserves insertion order)."""

  def __init__(self):
    self.grouped_ranges = {}

  def add(self, introduced_in, fixed_in, affected_in):
    """Add a new commit range."""
    # last_affected is redundant if fixed is available
    if fixed_in and affected_in:
      affected_in = None

    if introduced_in in self.grouped_ranges:
      if fixed_in is None and affected_in is None:
        # New range doesn't add anything new.
        return

      # Remove in-place as we need to preserve insertion order.
      existing_ranges = self.grouped_ranges[introduced_in]
      existing_ranges.append((introduced_in, fixed_in, affected_in))
      for value in existing_ranges.copy():
        # No fixed or last_affected commits
        if value[1] is None and value[2] is None:
          existing_ranges.remove(value)
          continue

        # Existing last_affected range which is no longer necessary. Now that we
        # have a fixed commit, use that instead.
        if fixed_in and value[1] is None and value[2] is not None:
          existing_ranges.remove(value)
    else:
      self.grouped_ranges[introduced_in] = [(introduced_in, fixed_in,
                                             affected_in)]

  def ranges(self):
    """Return a list representing the collected commit ranges."""
    commit_ranges = []
    for grouped_range in self.grouped_ranges.values():
      for commit_range in grouped_range:
        if commit_range not in commit_ranges:
          commit_ranges.append(commit_range)

    return commit_ranges


class RepoAnalyzer:
  """Repository analyzer."""

  def __init__(self, detect_cherrypicks=True):
    self.detect_cherrypicks = detect_cherrypicks

  def get_affected(self,
                   repo: pygit2.Repository,
                   regress_commits: list[str],
                   fix_commits: list[str],
                   limit_commits: list[str] = None,
                   last_affected_commits: list[str] = None):
    """"Get list of affected tags and commits for a bug given regressed and
    fixed commits."""
    affected_commits, affected_ranges, tags = self._get_affected_range(
        repo,
        regress_commits,
        last_affected_commits,
        fix_commits,
        limit_commits=limit_commits)

    return AffectedResult(tags, affected_commits, affected_ranges)

  def _get_affected_range(self,
                          repo: pygit2.Repository,
                          regress_commits: list[str],
                          last_affected_commits: list[str],
                          fix_commits: list[str],
                          limit_commits: list[str] = None):
    """Get affected range."""
    range_collector = RangeCollector()
    commits = set()
    seen_commits = set()
    tags = set()
    commits_to_tags = _get_commit_to_tag_mappings(repo)
    branch_to_limit = {}
    repo_url = None
    if 'origin' in repo.remotes.names():
      repo_url = repo.remotes['origin'].url

    branches = []
    detect_cherrypicks = self.detect_cherrypicks and not limit_commits
    if detect_cherrypicks and not last_affected_commits:
      # Check all branches for cherry picked regress/fix commits (sorted for
      # determinism).
      # If `last_affected` is provided at all, we can't do this, as we
      # cherry-pick detection does not make sense when it comes to
      # the `last_affected` commit.
      branches = sorted(repo.branches.remote)
    else:
      if limit_commits:
        for limit_commit in limit_commits:
          current_branches = _branches_with_commit(repo, limit_commit)
          for branch in current_branches:
            branch_to_limit[branch] = limit_commit

          branches.extend(current_branches)
      elif last_affected_commits:
        for last_affected_commit in last_affected_commits:
          branches.extend(_branches_with_commit(repo, last_affected_commit))
      elif fix_commits:
        # TODO(ochang): Remove this check. This behaviour should only be keyed
        # on `limit_commits`.
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
        logging.info('Finding equivalent regress commit to %s in %s in %s',
                     regress_commit, ref, repo_url)
        equivalent_regress_commit = self._get_equivalent_commit(
            repo, ref, regress_commit, detect_cherrypicks=detect_cherrypicks)
        if equivalent_regress_commit:
          break

      # If regress_commits is provided, then we should find an equivalent.
      if not equivalent_regress_commit and regress_commits:
        continue

      # Get the latest equivalent commit in the fix range.
      equivalent_fix_commit = None
      for fix_commit in fix_commits:
        logging.info('Finding equivalent fix commit to %s in %s in %s',
                     fix_commit, ref, str(repo_url or 'UNKNOWN_REPO_URL'))
        equivalent_fix_commit = self._get_equivalent_commit(
            repo, ref, fix_commit, detect_cherrypicks=detect_cherrypicks)
        if equivalent_fix_commit:
          break

      # Get the latest equivalent commit in the last_affected range (if
      # present).
      equivalent_last_affected_commit = None
      if last_affected_commits:
        for last_affected_commit in last_affected_commits:
          logging.info(
              'Finding equivalent last_affected commit to %s in %s in %s',
              last_affected_commit, ref, str(repo_url or 'UNKNOWN_REPO_URL'))
          equivalent_last_affected_commit = self._get_equivalent_commit(
              repo,
              ref,
              last_affected_commit,
              # last_affected does not work for cherrypick detection.
              detect_cherrypicks=False)
          if equivalent_last_affected_commit:
            break

      range_collector.add(equivalent_regress_commit, equivalent_fix_commit,
                          equivalent_last_affected_commit)

      if equivalent_fix_commit:
        end_commit = equivalent_fix_commit
        include_end = False
      elif equivalent_last_affected_commit:
        # Note: It's invalid to have both fix and last_affected. In such cases,
        # we prefer the fix due to it coming first in the if statements.
        end_commit = equivalent_last_affected_commit
        include_end = True
      else:
        # Not fixed in this branch. Everything is still vulnerable.
        end_commit = str(repo.revparse_single(ref).id)
        include_end = True

      if (equivalent_regress_commit, end_commit) in seen_commits:
        continue

      seen_commits.add((equivalent_regress_commit, end_commit))
      cur_commits, cur_tags = get_commit_and_tag_list(
          repo,
          equivalent_regress_commit,
          end_commit,
          commits_to_tags,
          include_start=True,
          include_end=include_end)
      commits.update(cur_commits)
      tags.update(cur_tags)

    # Add logical branches for commits not part of any upstream branches.
    for regress_commit in regress_commits:
      if not any(branch for branch in branches if regress_commit in _get_commit_branch(repo, branch)):
        commits.add(regress_commit)

    for fix_commit in fix_commits:
      if not any(branch for branch in branches if fix_commit in _get_commit_branch(repo, branch)):
        commits.add(fix_commit)

    return commits, range_collector.ranges(), tags

  def _get_equivalent_commit(self,
                             repo,
                             ref,
                             target_commit,
                             detect_cherrypicks=False):
    """Return an equivalent commit to target_commit that is in ref."""
    commit = repo.revparse_single(ref)
    max_topo_order = commit.topo_order
    for cur in repo.walk(commit.id, pygit2.GIT_SORT_TIME):
      if max_topo_order is not None and cur.topo_order > max_topo_order:
        break

      if detect_cherrypicks and cur.message == repo[target_commit].message:
        return str(cur.id)

      if str(cur.id) == target_commit:
        return target_commit

    return None


def _get_commit_to_tag_mappings(repo):
  """Get commit to tag mappings."""
  commit_to_tag = {}
  for ref_name in repo.references:
    if ref_name.startswith(TAG_PREFIX):
      commit = repo.references[ref_name].peel()
      if commit.type != pygit2.GIT_OBJ_COMMIT:
        continue

      commit_id = str(commit.id)
      if commit_id not in commit_to_tag:
        commit_to_tag[commit_id] = set()

      commit_to_tag[commit_id].add(ref_name[len(TAG_PREFIX):])

  return commit_to_tag


def get_commit_and_tag_list(repo,
                            start_commit,
                            end_commit,
                            commits_to_tags,
                            include_start=True,
                            include_end=True):
  """Get list of commits and tags between a range."""
  commits = []
  tags = set()
  for cur in repo.walk(repo.revparse_single(start_commit).id,
                       pygit2.GIT_SORT_TIME | pygit2.GIT_SORT_TOPOLOGICAL):
    if not include_start and str(cur.id) == start_commit:
      continue

    if not include_end and str(cur.id) == end_commit:
      break

    commits.append(str(cur.id))
    if str(cur.id) in commits_to_tags:
      tags.update(commits_to_tags[str(cur.id)])

    if str(cur.id) == end_commit:
      break

  return commits, tags


def _branches_with_commit(repo, commit):
  """Get list of branches containing a commit."""
  branches = []
  for branch in repo.branches.remote:
    for cur in repo.walk(repo.revparse_single('refs/remotes/' + branch).id,
                         pygit2.GIT_SORT_TIME | pygit2.GIT_SORT_TOPOLOGICAL):
      if str(cur.id) == commit:
        branches.append(branch)
        break

  return branches


def _get_commit_branch(repo, branch):
  """Get the commit id for a branch."""
  return [str(commit.id) for commit in repo.walk(repo.revparse_single('refs/remotes/' + branch).id, pygit2.GIT_SORT_TIME | pygit2.GIT_SORT_TOPOLOGICAL)]


def analyze(vulnerability, analyze_git=True):
  """Analyze."""
  logging.info('Analyzing vulnerability %s', vulnerability.key.id())
  tags = set()
  commits = set()
  affected_commits = set()

  if analyze_git:
    analyze_result = analyze_git_vulnerability(vulnerability)
    if analyze_result:
      tags.update(analyze_result.tags)
      commits.update(analyze_result.commits)
      affected_commits.update(analyze_result.affected_commits)

  has_changes = False
  if tags != vulnerability.tags or commits != vulnerability.commits:
    has_changes = True
    vulnerability.tags = tags
    vulnerability.commits = commits

  return AnalyzeResult(has_changes, affected_commits)
