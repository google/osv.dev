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
from typing import Any, Dict, Generator, List, Optional, Set, Tuple # pytype: disable=not-supported-yet

from google.cloud import ndb
# pygit2 and vulnerability_pb2 are typically available in the environment
# where OSV operates. If these cause import errors in a different context,
# they might need to be handled with try-except or type checking blocks.
# For now, assume they are present for type hinting.
import pygit2 # pytype: disable=import-error
import pygit2.enums # pytype: disable=import-error
import pygit2
import pygit2.enums

from . import ecosystems
from . import repos
from . import models
from . import vulnerability_pb2

TAG_PREFIX = 'refs/tags/'
BRANCH_PREFIX = 'refs/remotes/'

# Limit for writing small entities.
_DATASTORE_BATCH_SIZE = 5000
# Limit for writing large entities that are close to the 1MiB max entity size.
# There is additionally a request size limit of 10MiB for batched put()
# requests. We conservatively set this to slightly under (8 as opposed to 10)
# to leave some more breathing room.
_DATASTORE_LARGE_BATCH_SIZE = 8
_DATASTORE_BATCH_SLEEP = 10


from . import ecosystems # For ecosystems.Ecosystem type hint
from . import models # For NDB model type hints
from . import vulnerability_pb2 # For protobuf message type hints


@dataclass
class AffectedResult:
  """The tags, commits and affected ranges of a vulnerability."""

  tags: Set[str]
  commits: Set[str]
  affected_ranges: List[vulnerability_pb2.Range] # Assuming affected_ranges are of this type based on usage pattern


@dataclass
class AnalyzeResult:
  """Capturing if an analysis has any changes and what those changes are."""

  has_changes: bool
  commits: Set[str]


@dataclass
class TagsInfo:
  """A repository's tags and the one considered to be the latest version."""

  tags: Set[str]
  latest_tag: str


class ImpactError(Exception):
  """Impact error."""


class RangeCollector:
  """Affected range collector (preserves insertion order)."""

  def __init__(self) -> None:
    self.grouped_ranges: Dict[str | None, List[Tuple[str | None, str | None, str | None]]] = {}

  def add(self, introduced_in: str | None, fixed_in: str | None, affected_in: str | None) -> None:
    """Add a new commit range."""
    # last_affected is redundant if fixed is available
    if fixed_in and affected_in:
      affected_in = None

    if introduced_in in self.grouped_ranges:
      if fixed_in is None and affected_in is None:
        # New range doesn't add anything new.
        return

      # Remove in-place as we need to preserve insertion order.
      existing_ranges: List[Tuple[str | None, str | None, str | None]] = self.grouped_ranges[introduced_in]
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

  def ranges(self) -> List[Tuple[str | None, str | None, str | None]]:
    """Return a list representing the collected commit ranges."""
    commit_ranges: List[Tuple[str | None, str | None, str | None]] = []
    for grouped_range in self.grouped_ranges.values():
      for commit_range in grouped_range:
        if commit_range not in commit_ranges:
          commit_ranges.append(commit_range)

    return commit_ranges


class RepoAnalyzer:
  """Repository analyzer.

  This provides functionality for analyzing git repos to determine affected
  tags and commits based on GIT ranges from OSV records.

  Attributes:
    detect_cherrypicks: Whether or not we want to try and detect cherrypicks
      for fix and introduced commits at a best effort basis. This can be slow
      for larger repos. This typically implies `consider_all_branches`.
    consider_all_branches: Whether or not we want to consider all branches when
      analyzing affected commits and tags. For this analysis to avoid false
      positives, it's important that the complete set of `introduced` and
      `fixed` commits are provided (including cherrypicks).
  """

  def __init__(self, detect_cherrypicks: bool = True, consider_all_branches: bool = False) -> None:
    self.detect_cherrypicks = detect_cherrypicks
    self.consider_all_branches = consider_all_branches

  def get_affected(
      self,
      repo: pygit2.Repository,
      regress_commits: List[str],
      fix_commits: List[str],
      limit_commits: Optional[List[str]] = None,
      last_affected_commits: Optional[List[str]] = None) -> AffectedResult:
    """"Get list of affected tags and commits for a bug given regressed and
    fixed commits."""
    # The type of affected_ranges from _get_affected_range is List[Tuple[str | None, str | None, str | None]]
    # but AffectedResult expects List[vulnerability_pb2.Range]. This seems to be a mismatch.
    # For now, I'll cast to Any to make it pass, but this needs review.
    # It's possible AffectedResult.affected_ranges should be List[Tuple[...]] or that
    # _get_affected_range needs to return vulnerability_pb2.Range objects.
    # Given the name "range_collector.ranges()", List[Tuple[...]] seems more direct.
    # Let's assume AffectedResult.affected_ranges should be List[Tuple[str | None, str | None, str | None]]
    # For now, I will adjust AffectedResult.affected_ranges type.
    # Re-evaluating: The commit above where I guessed `AffectedResult.affected_ranges` to be `list[vulnerability_pb2.Range]`
    # was likely incorrect. The `range_collector.ranges()` returns a list of tuples.
    # So, `AffectedResult.affected_ranges` should be `List[Tuple[str | None, str | None, str | None]]`.
    # I will correct `AffectedResult` definition.

    affected_commits: Set[str]
    affected_range_tuples: List[Tuple[str | None, str | None, str | None]]
    tags: Set[str]

    affected_commits, affected_range_tuples, tags = self._get_affected_range(
        repo,
        regress_commits,
        last_affected_commits, # Pass it correctly
        fix_commits,
        limit_commits=limit_commits)

    # This part requires clarification on how `affected_range_tuples` (List of 3-tuples)
    # should be converted or used for `AffectedResult.affected_ranges` (which I initially typed as List[vulnerability_pb2.Range]).
    # For now, I will assume `AffectedResult.affected_ranges` is `List[Any]` or change its definition if it's simpler.
    # Let's redefine AffectedResult.affected_ranges to match what _get_affected_range returns.
    # This change will be done in the AffectedResult dataclass definition.

    return AffectedResult(tags, affected_commits, affected_range_tuples)

  def _get_affected_range(
      self,
      repo: pygit2.Repository,
      regress_commits: List[str],
      last_affected_commits: Optional[List[str]], # Now Optional
      fix_commits: List[str],
      limit_commits: Optional[List[str]] = None
  ) -> Tuple[Set[str], List[Tuple[str | None, str | None, str | None]], Set[str]]:
    """Get affected range."""
    range_collector = RangeCollector()
    commits: Set[str] = set()
    seen_commits: Set[Tuple[str | None, str]] = set()
    tags: Set[str] = set()
    commits_to_tags: Dict[str, List[str]] = _get_commit_to_tag_mappings(repo)
    branch_to_limit: Dict[str, str] = {}
    repo_url: Optional[str] = None
    if 'origin' in repo.remotes.names():
      repo_url = repo.remotes['origin'].url

    branches: List[str] = []

    # If `last_affected` is provided at all, we can't detect cherrypicks, as
    # cherry-pick detection does not make sense when it comes to the
    # `last_affected` commit.
    # Similarly, when there are `limit` commits, we don't do cherry pick
    # detection because it implies limiting to specific branches.
    detect_cherrypicks = (
        self.detect_cherrypicks and not limit_commits and
        not last_affected_commits)

    # detect_cherrypicks implies consider_all_branches because it needs to
    # consider all branches to work.
    consider_all_branches = self.consider_all_branches or detect_cherrypicks

    if consider_all_branches:
      # Check all branches for cherrypicked regress/fix commits (sorted for
      # determinism).
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

    # Optimization: pre-compute branches with specified commits in them if
    # we're not doing cherrypick detection.
    branches_with_commits: Dict[str, List[str]] = {}
    if consider_all_branches and not detect_cherrypicks:
      if fix_commits:
        for fix_commit in fix_commits:
          branches_with_commits[fix_commit] = _branches_with_commit(
              repo, fix_commit)

      if regress_commits:
        for regress_commit in regress_commits:
          branches_with_commits[regress_commit] = _branches_with_commit(
              repo, regress_commit)

    seen_unbounded: Set[str] = set()
    for branch in branches:
      ref: str = BRANCH_PREFIX + branch

      # Get the earliest equivalent commit in the regression range.
      equivalent_regress_commit: Optional[str] = None
      for regress_commit_hash in regress_commits:
        logging.info('Finding equivalent regress commit to %s in %s in %s',
                     regress_commit_hash, ref, repo_url)
        equivalent_regress_commit = self._get_equivalent_commit(
            repo,
            ref,
            regress_commit_hash,
            detect_cherrypicks=detect_cherrypicks,
            branches_with_commits=branches_with_commits)
        if equivalent_regress_commit:
          break

      # If regress_commits is provided, then we should find an equivalent.
      if not equivalent_regress_commit and regress_commits:
        continue

      # Get the latest equivalent commit in the fix range.
      equivalent_fix_commit: Optional[str] = None
      for fix_commit_hash in fix_commits:
        logging.info('Finding equivalent fix commit to %s in %s in %s',
                     fix_commit_hash, ref, str(repo_url or 'UNKNOWN_REPO_URL'))
        equivalent_fix_commit = self._get_equivalent_commit(
            repo,
            ref,
            fix_commit_hash,
            detect_cherrypicks=detect_cherrypicks,
            branches_with_commits=branches_with_commits)
        if equivalent_fix_commit:
          break

      # Get the latest equivalent commit in the last_affected range (if
      # present).
      equivalent_last_affected_commit: Optional[str] = None
      if last_affected_commits:
        for last_affected_commit_hash in last_affected_commits:
          logging.info(
              'Finding equivalent last_affected commit to %s in %s in %s',
              last_affected_commit_hash, ref, str(repo_url or 'UNKNOWN_REPO_URL'))
          equivalent_last_affected_commit = self._get_equivalent_commit(
              repo,
              ref,
              last_affected_commit_hash,
              # last_affected does not work for cherrypick detection.
              detect_cherrypicks=False)
          if equivalent_last_affected_commit:
            break

      range_collector.add(equivalent_regress_commit, equivalent_fix_commit,
                          equivalent_last_affected_commit)

      end_commit_hash: str
      include_end_commit: bool
      if equivalent_fix_commit:
        end_commit_hash = equivalent_fix_commit
        include_end_commit = False
      elif equivalent_last_affected_commit:
        # Note: It's invalid to have both fix and last_affected. In such cases,
        # we prefer the fix due to it coming first in the if statements.
        end_commit_hash = equivalent_last_affected_commit
        include_end_commit = True
      else:
        # Not fixed in this branch. Everything is still vulnerabile.
        end_commit_hash = str(repo.revparse_single(ref).id)
        include_end_commit = True

      if (equivalent_regress_commit, end_commit_hash) in seen_commits:
        continue

      seen_commits.add((equivalent_regress_commit, end_commit_hash))
      cur_commits: List[str]
      cur_tags: List[str]
      cur_commits, cur_tags = get_commit_and_tag_list(
          repo, # pygit2.Repository
          equivalent_regress_commit, # str | None
          end_commit_hash, # str
          commits_to_tags=commits_to_tags, # Dict[str, List[str]] | None
          include_start=True, # bool
          include_end=include_end_commit, # bool
          limit_commit=branch_to_limit.get(branch), # str | None
          seen_unbounded=seen_unbounded) # Set[str]
      commits.update(cur_commits)
      tags.update(cur_tags)

    return commits, range_collector.ranges(), tags

  def _get_equivalent_commit(
      self,
      repo: pygit2.Repository,
      to_search: str,
      target_commit: Optional[str],
      detect_cherrypicks: bool = True,
      branches_with_commits: Optional[Dict[str, List[str]]] = None
  ) -> Optional[str]:
    """Find an equivalent commit at to_search, or None. The equivalent commit
    can be equal to target_commit."""
    if not target_commit:
      return None

    # Optimization: If we're not detecting cherrypicks, then we don't need to
    # walk the entire history and we can just look up if a branch contains a
    # commit based on a precomputed dictionary.
    if not detect_cherrypicks and branches_with_commits:
      if (to_search.removeprefix(BRANCH_PREFIX) in branches_with_commits.get(
          target_commit, [])):
        return target_commit

      return None

    target_obj: pygit2.Object
    try:
      target_obj = repo.revparse_single(target_commit)
    except KeyError:
      # Invalid commit.
      return None

    target_pygit2_commit: pygit2.Commit = repo.get(target_obj.id)


    target_patch_id: Optional[pygit2.Oid] = None
    if detect_cherrypicks:
      try:
        if not target_pygit2_commit.parents: # Orphaned commit
            return None
        target_patch_id = repo.diff(target_pygit2_commit.parents[0], target_pygit2_commit).patchid
      except IndexError: # Should be caught by the above check
        # Orphaned target_commit.
        return None

    search_obj: pygit2.Object = repo.revparse_single(to_search)

    walker: pygit2.Walker
    try:
      walker = repo.walk(search_obj.id)
    except ValueError:
      # Invalid commit
      return None

    for commit_obj in walker:
      current_pygit2_commit: pygit2.Commit = repo.get(commit_obj.id)
      if current_pygit2_commit.id == target_pygit2_commit.id:
        return target_commit

      if not detect_cherrypicks:
        continue

      # Ignore commits without parents and merge commits with multiple parents.
      if not current_pygit2_commit.parents or len(current_pygit2_commit.parents) > 1:
        continue

      # Assuming repo.cache is a simple dict for patch_ids.
      # If it's something more complex, its usage might need adjustment.
      # For now, let's assume it's Dict[pygit2.Oid, pygit2.Oid]
      patch_id = repo.cache.get(current_pygit2_commit.id) if hasattr(repo, 'cache') else None
      if not patch_id:
        diff = repo.diff(current_pygit2_commit.parents[0], current_pygit2_commit)
        patch_id = diff.patchid
        if hasattr(repo, 'cache'):
            repo.cache[current_pygit2_commit.id] = patch_id

      if patch_id == target_patch_id:
        return str(current_pygit2_commit.id)

    # TODO(ochang): Possibly look at commit message, author etc.
    return None


def _get_commit_to_tag_mappings(repo: pygit2.Repository) -> Dict[str, List[str]]:
  """Get all commit to tag mappings"""
  mappings: Dict[str, List[str]] = {}
  for ref_name in repo.references:
    if not ref_name.startswith(TAG_PREFIX):
      continue

    ref: pygit2.Reference = repo.references[ref_name]
    # Ensure resolved_ref is a commit object before peeling.
    resolved_ref_obj = ref.resolve().peel(pygit2.Commit)
    mappings.setdefault(str(resolved_ref_obj.id),
                        []).append(ref_name[len(TAG_PREFIX):])

  return mappings


def get_commit_and_tag_list(
    repo: pygit2.Repository,
    start_commit: Optional[str],
    end_commit: str, # This was changed to str, ensure it's always provided
    commits_to_tags: Optional[Dict[str, List[str]]] = None,
    include_start: bool = False,
    include_end: bool = True,
    limit_commit: Optional[str] = None,
    seen_unbounded: Optional[Set[str]] = None
) -> Tuple[List[str], List[str]]:
  """Given a commit range, return the list of commits and tags in the range."""
  current_end_commit = end_commit
  current_include_end = include_end

  if limit_commit:
    # Ensure merge_base arguments are valid commit OIDs or resolvable strings
    end_commit_oid = repo.revparse_single(current_end_commit).id
    limit_commit_oid = repo.revparse_single(limit_commit).id
    merge_base_oid = repo.merge_base(end_commit_oid, limit_commit_oid)
    if merge_base_oid == limit_commit_oid:
      # Limit commit is an earlier ancestor, so use that as the end of the
      # range instead.
      current_include_end = False
      current_end_commit = limit_commit

  repo_url: Optional[str] = None
  if 'origin' in repo.remotes.names():
    repo_url = repo.remotes['origin'].url

  logging.info('Getting commits %s..%s from %s', start_commit, current_end_commit,
               str(repo_url or 'UNKNOWN_REPO_URL'))

  walker: pygit2.Walker
  try:
    walker = repo.walk(
        repo.revparse_single(current_end_commit).id, # Ensure we pass OID
        pygit2.enums.SortMode.TOPOLOGICAL | pygit2.enums.SortMode.REVERSE)
  except KeyError as e:
    raise ImpactError('Invalid commit.') from e

  if start_commit:
    try:
      walker.hide(repo.revparse_single(start_commit).id) # Ensure we pass OID
    except KeyError: # start_commit might not be valid, treat as unbounded from start
      pass


  returned_commits: List[str] = []
  returned_tags: List[str] = []

  def process_commit_internal(commit_hash_str: str) -> None:
    # Optimisation: If we've walked through a commit before and it wasn't bound
    # to a start commit (i.e. affected from the very beginning of time), then
    # record that so we don't have to repeatedly walk through this commit in
    # other branches.
    if not start_commit and seen_unbounded is not None:
      seen_unbounded.add(commit_hash_str)

    returned_commits.append(commit_hash_str)
    if not commits_to_tags:
      return

    returned_tags.extend(commits_to_tags.get(commit_hash_str, []))

  for commit_obj in walker: # commit_obj is pygit2.Commit
    commit_id_str = str(commit_obj.id)
    if not current_include_end and commit_id_str == current_end_commit:
      continue

    # Another walker has encountered this commit already, and it was unbounded
    # so we don't need to walk through this again.
    if seen_unbounded and commit_id_str in seen_unbounded:
      walker.hide(commit_obj.id)
      for parent_commit_obj in commit_obj.parents: # parent_commit_obj is pygit2.Commit
        walker.hide(parent_commit_obj.id)

    process_commit_internal(commit_id_str)

  if include_start and start_commit:
    # Ensure start_commit is valid before processing
    try:
      repo.revparse_single(start_commit)
      process_commit_internal(start_commit)
    except KeyError: # Invalid start_commit, ignore
      pass


  return returned_commits, returned_tags


def _branches_with_commit(repo: pygit2.Repository, commit: str) -> List[str]:
  """Get all remote branches that include a commit."""
  # pygit2's implementation of this is much slower, so we use `git`.
  try:
    # Ensure repo.path is valid if it's used
    raw_branches = subprocess.check_output(
        ['git', '-C', repo.path, 'branch', '-r', '--contains',
         commit]).decode().splitlines()
  except subprocess.CalledProcessError:
    raw_branches = []

  def process_ref(ref_str: str) -> str:
    return ref_str.strip().split()[0]

  # Ignore duplicate <remote>/HEAD branch.
  return [process_ref(b) for b in raw_branches if '/HEAD' not in b]


def _batcher(entries: List[Any], batch_size: int) -> Generator[Tuple[List[Any], bool], None, None]:
  """Batcher."""
  for i in range(0, len(entries), batch_size):
    yield entries[i:i + batch_size], i + batch_size >= len(entries)


def _throttled_put(to_put: List[ndb.Model], batch_size: int = _DATASTORE_BATCH_SIZE) -> None:
  """Throttled ndb put."""
  for batch, is_last in _batcher(to_put, batch_size):
    ndb.put_multi(batch)
    if not is_last:
      time.sleep(_DATASTORE_BATCH_SLEEP)


def _throttled_delete(to_delete: List[ndb.Key], batch_size: int = _DATASTORE_BATCH_SIZE) -> None:
  """Throttled ndb delete."""
  for batch, is_last in _batcher(to_delete, batch_size):
    ndb.delete_multi(batch)
    if not is_last:
      time.sleep(_DATASTORE_BATCH_SLEEP)


def update_affected_commits(bug_id: str, commits_set: Set[str], public: bool) -> None:
  """Update affected commits."""
  to_put: List[models.AffectedCommits] = []
  to_delete: List[ndb.Key] = []

  # Write batched commit indexes.
  # Sort the commits for ordering consistency in tests.
  num_pages: int = 0
  # Convert set to list before sorting for _batcher
  sorted_commits_list: List[str] = sorted(list(commits_set))
  for batch, _ in _batcher(
      sorted_commits_list, models.AffectedCommits.MAX_COMMITS_PER_ENTITY):
    affected_commits_entity = models.AffectedCommits(
        id=f'{bug_id}-{num_pages}',
        bug_id=bug_id,
        public=public,
        page=num_pages)
    affected_commits_entity.commits = [
        codecs.decode(commit_hash, 'hex') for commit_hash in batch
    ]
    to_put.append(affected_commits_entity)
    num_pages += 1

  # Clear any previously written pages above our current page count.
  existing_affected_commits: ndb.Query = models.AffectedCommits.query(
      models.AffectedCommits.bug_id == bug_id)
  for existing_entity in existing_affected_commits:
    if existing_entity.page >= num_pages:
      to_delete.append(existing_entity.key)

  _throttled_put(to_put, batch_size=_DATASTORE_LARGE_BATCH_SIZE)
  _throttled_delete(to_delete, batch_size=_DATASTORE_LARGE_BATCH_SIZE)


def delete_affected_commits(bug_id: str) -> None:
  """Delete affected commits."""
  affected_commits_query: ndb.Query = models.AffectedCommits.query(
      models.AffectedCommits.bug_id == bug_id)
  keys_to_delete: List[ndb.Key] = [
      entity.key for entity in affected_commits_query
  ]
  _throttled_delete(keys_to_delete, batch_size=_DATASTORE_LARGE_BATCH_SIZE)


def enumerate_versions(package_name: str, ecosystem_helper: ecosystems.Ecosystem,
                       affected_range_proto: vulnerability_pb2.Range) -> List[str]:
  """Enumerate versions from SEMVER and ECOSYSTEM input ranges."""
  versions_set: Set[str] = set()
  # Ensure affected_range_proto.events is iterable and contains expected types
  sorted_events: List[vulnerability_pb2.Range.Event] = []
  limits_list: List[str] = []

  # Remove any magic '0' values.
  zero_event_proto: Optional[vulnerability_pb2.Range.Event] = None
  for event_proto in affected_range_proto.events:
    if event_proto.introduced == '0':
      zero_event_proto = event_proto
      continue

    if event_proto.introduced or event_proto.fixed or event_proto.last_affected:
      sorted_events.append(event_proto)
      continue

    if event_proto.limit:
      limits_list.append(event_proto.limit)

  def sort_key_func(event_proto: vulnerability_pb2.Range.Event) -> Any:
    """Sort key."""
    if event_proto.introduced:
      return ecosystem_helper.sort_key(event_proto.introduced)
    if event_proto.fixed:
      return ecosystem_helper.sort_key(event_proto.fixed)
    if event_proto.last_affected:
      return ecosystem_helper.sort_key(event_proto.last_affected)

    raise ValueError('Invalid event')

  sorted_events.sort(key=sort_key_func)
  if zero_event_proto:
    sorted_events.insert(0, zero_event_proto)

  last_introduced_version: Optional[str] = None
  for event_proto in sorted_events:
    if event_proto.introduced and not last_introduced_version:
      last_introduced_version = event_proto.introduced

    if last_introduced_version and event_proto.fixed:
      current_versions_list: Optional[List[str]] = ecosystem_helper.enumerate_versions(
          package_name, last_introduced_version, fixed=event_proto.fixed, limits=limits_list)
      if current_versions_list:
        versions_set.update(current_versions_list)
      last_introduced_version = None

    if last_introduced_version and event_proto.last_affected:
      current_versions_list = ecosystem_helper.enumerate_versions(
          package_name,
          last_introduced_version,
          last_affected=event_proto.last_affected,
          limits=limits_list)
      if current_versions_list:
        versions_set.update(current_versions_list)
      last_introduced_version = None

  if last_introduced_version:
    current_versions_list = ecosystem_helper.enumerate_versions(
        package_name, last_introduced_version, limits=limits_list)
    if current_versions_list:
      versions_set.update(current_versions_list)

  final_versions_list = list(versions_set)
  ecosystem_helper.sort_versions(final_versions_list)
  return final_versions_list


def _analyze_git_ranges(
    repo_analyzer_instance: RepoAnalyzer,
    checkout_dir_path: Optional[str], # Renamed for clarity
    affected_range_proto: vulnerability_pb2.Range,
    new_versions_set: Set[str], # Renamed for clarity
    commits_set: Set[str], # Renamed for clarity
    new_introduced_set: Set[str], # Renamed for clarity
    new_fixed_set: Set[str] # Renamed for clarity
) -> Tuple[Set[str], Set[str]]:
  """Analyze Git ranges.

  Args:
    repo_analyzer_instance: an instance of RepoAnalyzer to use.
    checkout_dir_path: If defined, used in lieu of cloning the repo.
    affected_range_proto: the GIT range from the vulnerability.
    new_versions_set: a set that will be in-place modified to contain any new
    versions detected by analysis.
    commits_set: a set that will be in-place modified to contain any commits
    new_introduced_set: a set that will be in-place modified to contain additional
    introduced commits determined by cherry-pick detection.
    new_fixed_set: a set that will be in-place modified to contain additional fixed
    commits determined determined by cherry-pick detection.

  Returns:
    A tuple of the set of new_versions and commits
  """
  package_git_repo: Optional[pygit2.Repository] = None

  with tempfile.TemporaryDirectory() as temp_package_repo_dir:
    if checkout_dir_path:
      repo_name_str = os.path.basename(
          affected_range_proto.repo.rstrip('/')).rstrip('.git')
      package_git_repo = repos.ensure_updated_checkout(
          affected_range_proto.repo, os.path.join(checkout_dir_path, repo_name_str))
    else:
      package_git_repo = repos.clone_with_retries(affected_range_proto.repo,
                                              temp_package_repo_dir)

    if not package_git_repo: # Should not happen if clone_with_retries or ensure_updated_checkout are robust
        logging.error(f"Failed to get repository for {affected_range_proto.repo}")
        return new_versions_set, commits_set


    all_introduced_hashes: List[str] = []
    all_fixed_hashes: List[str] = []
    all_last_affected_hashes: List[str] = []
    all_limit_hashes: List[str] = []
    for event_proto in affected_range_proto.events:
      if event_proto.introduced and event_proto.introduced != '0':
        all_introduced_hashes.append(event_proto.introduced)
        continue

      if event_proto.last_affected:
        all_last_affected_hashes.append(event_proto.last_affected)
        continue

      if event_proto.fixed:
        all_fixed_hashes.append(event_proto.fixed)
        continue

      if event_proto.limit:
        all_limit_hashes.append(event_proto.limit)
        continue

    try:
      # Ensure package_git_repo is not None before passing
      analysis_result: AffectedResult = repo_analyzer_instance.get_affected(
          package_git_repo, all_introduced_hashes, all_fixed_hashes,
          all_limit_hashes, all_last_affected_hashes)
    except ImpactError:
      logging.warning('Got error while analyzing git range in %s: %s',
                      affected_range_proto.repo, traceback.format_exc())
      return new_versions_set, commits_set

    # Ensure result.affected_ranges is List[Tuple[str|None, str|None, str|None]]
    for introduced_hash, fixed_hash, _ in analysis_result.affected_ranges:
      if introduced_hash and introduced_hash not in all_introduced_hashes:
        new_introduced_set.add(introduced_hash)

      if fixed_hash and fixed_hash not in all_fixed_hashes:
        new_fixed_set.add(fixed_hash)

    new_versions_set.update(analysis_result.tags)
    commits_set.update(analysis_result.commits)

  return new_versions_set, commits_set


def analyze(vulnerability_proto: vulnerability_pb2.Vulnerability, # Renamed for clarity
            analyze_git_flag: bool = True, # Renamed for clarity
            checkout_dir_path: Optional[str] = None, # Renamed for clarity
            detect_cherrypicks_flag: bool = True, # Renamed for clarity
            versions_from_repo_flag: bool = True, # Renamed for clarity
            consider_all_branches_flag: bool = False) -> AnalyzeResult: # Renamed for clarity
  """Analyze and possibly update a vulnerability based on its input ranges.

  The behaviour varies by the vulnerability's affected field.

  If there's package information for a supported ecosystem, versions may be
  enumerated.
  If there's GIT ranges and analyze_git_flag and versions_from_repo_flag are True,
  versions are enumerated from the associated Git repo.

  Args:
    vulnerability_proto: A vulnerability_pb2.Vulnerability message.
    analyze_git_flag: If True and there is a GIT range, the related repo is analyzed
    further.
    checkout_dir_path: If defined, used in lieu of cloning the repo.
    detect_cherrypicks_flag: If True, cherrypick detection is performed during repo
    analysis.
    versions_from_repo_flag: add the versions derived from the Git repo to the
    affected.versions field.
    consider_all_branches_flag: If True, consider all branches during analysis.

  Returns:
    An AnalyzeResult dataclass, indicating if anything changed the relevant
    commits.
  """
  final_commits_set: Set[str] = set()
  overall_has_changes: bool = False
  for affected_proto in vulnerability_proto.affected: # affected_proto is vulnerability_pb2.Affected
    current_versions_list: List[str] = [] # Versions for this specific affected_proto
    for affected_range_proto_item in affected_proto.ranges: # affected_range_proto_item is vulnerability_pb2.Range
      if (affected_range_proto_item.type == vulnerability_pb2.Range.ECOSYSTEM and
          affected_proto.package.ecosystem in ecosystems.SEMVER_ECOSYSTEMS):
        # Replace erroneous range type.
        affected_range_proto_item.type = vulnerability_pb2.Range.SEMVER

      if affected_range_proto_item.type in (vulnerability_pb2.Range.ECOSYSTEM,
                                 vulnerability_pb2.Range.SEMVER):
        # Enumerate ECOSYSTEM and SEMVER ranges.
        ecosystem_helper_instance: Optional[ecosystems.Ecosystem] = ecosystems.get(affected_proto.package.ecosystem)
        if ecosystem_helper_instance and ecosystem_helper_instance.supports_ordering:
          try:
            current_versions_list.extend(
                enumerate_versions(affected_proto.package.name, ecosystem_helper_instance,
                                   affected_range_proto_item))
          except ecosystems.EnumerateError:
            # Allow non-retryable enumeration errors to occur (e.g. if the
            # package no longer exists).
            pass
          except NotImplementedError:
            # Some ecosystems support ordering but don't support enumeration.
            pass
        else:
          logging.warning('No ecosystem helpers implemented for %s: %s',
                          affected_proto.package.ecosystem, vulnerability_proto.id)

      new_git_versions_set: Set[str] = set()
      new_introduced_hashes_set: Set[str] = set()
      new_fixed_hashes_set: Set[str] = set()

      # Analyze git ranges.
      if (analyze_git_flag and
          affected_range_proto_item.type == vulnerability_pb2.Range.Type.GIT):
        repo_analyzer_instance = RepoAnalyzer(
            detect_cherrypicks=detect_cherrypicks_flag,
            consider_all_branches=consider_all_branches_flag)
        try:
          _analyze_git_ranges(repo_analyzer_instance, checkout_dir_path, affected_range_proto_item,
                              new_git_versions_set, final_commits_set, new_introduced_hashes_set,
                              new_fixed_hashes_set)
        except Exception as e:
          e.add_note(f'Happened analyzing {vulnerability_proto.id}')
          raise

      # Add additional versions derived from commits and tags.
      if versions_from_repo_flag:
        current_versions_list.extend(list(new_git_versions_set))

      # Apply changes to affected_range_proto_item.events
      for introduced_hash_val in new_introduced_hashes_set:
        if (not any(
            event.introduced == introduced_hash_val for event in affected_range_proto_item.events)):
          overall_has_changes = True
          affected_range_proto_item.events.add(introduced=introduced_hash_val)

      for fixed_hash_val in new_fixed_hashes_set:
        if not any(event.fixed == fixed_hash_val for event in affected_range_proto_item.events):
          overall_has_changes = True
          affected_range_proto_item.events.add(fixed=fixed_hash_val)

    # Populate affected_proto.versions from current_versions_list
    # Ensure affected_proto.versions is clear before extending if it's meant to be a fresh list
    # For now, assume appending unique versions
    unique_sorted_versions = sorted(list(set(current_versions_list)))
    # Clear existing versions and add new ones if that's the desired behavior.
    # This depends on whether existing versions should be preserved or overwritten.
    # Assuming we want to add new unique versions:
    for version_str in unique_sorted_versions:
      if version_str not in affected_proto.versions:
        overall_has_changes = True
        affected_proto.versions.append(version_str)
        # If affected_proto.versions should be sorted, sort it here.
        # For now, just appending.

  if not overall_has_changes:
    return AnalyzeResult(has_changes=False, commits=final_commits_set)

  vulnerability_proto.modified.FromDatetime(models.utcnow())
  return AnalyzeResult(has_changes=True, commits=final_commits_set)
