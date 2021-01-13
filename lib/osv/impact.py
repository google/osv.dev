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
import tempfile
import time

import pygit2

CLONE_TRIES = 3
COMMIT_RANGE_LIMIT = 4
CONFIDENCE_FULL = 100
# Flat reduction in confidence for any range.
CONFIDENCE_RANGE_REDUCTION = 20
# Reduction in confidence per commit in a range.
CONFIDENCE_RANGE_REDUCTION_STEP = 10
RETRY_SLEEP_SECONDS = 5

TAG_PREFIX = 'refs/tags/'

# Used in cases where an earlier commit in a regression range cannot be
# determined.
UNKNOWN_COMMIT = 'unknown'

AffectedResult = collections.namedtuple(
    'AffectedResult',
    'tags commits affected_ranges regress_commits fix_commits confidence')

TagsInfo = collections.namedtuple('TagsInfo', 'tags latest_tag')


class ImpactError(Exception):
  """Impact error."""


def clone_with_retries(git_url, checkout_dir):
  """Clone with retries."""
  logging.info('Cloning %s to %s', git_url, checkout_dir)
  for _ in range(CLONE_TRIES):
    try:
      repo = pygit2.clone_repository(git_url, checkout_dir)
      repo.cache = {}
      return repo
    except pygit2.GitError as e:
      logging.error('Clone failed: %s', str(e))
      time.sleep(RETRY_SLEEP_SECONDS)
      continue


def get_affected(git_url, regress_commit_or_range, fix_commit_or_range):
  """"Get list of affected tags and commits for a bug given regressed and fixed
  commits."""
  confidence = CONFIDENCE_FULL

  with tempfile.TemporaryDirectory() as tmp_dir:
    repo = clone_with_retries(git_url, tmp_dir)

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
      confidence -= CONFIDENCE_RANGE_REDUCTION

    # For every extra commit in the range, reduce the confidence.
    if len(regress_commits) > 1:
      confidence -= CONFIDENCE_RANGE_REDUCTION
      confidence -= (len(regress_commits) - 1) * CONFIDENCE_RANGE_REDUCTION_STEP

    # Special case: unknown status for earlier revisions.
    unknown_earlier_revisions = UNKNOWN_COMMIT in regress_commit_or_range
    if unknown_earlier_revisions:
      confidence -= CONFIDENCE_RANGE_REDUCTION

    if len(fix_commits) > 1:
      confidence -= CONFIDENCE_RANGE_REDUCTION
      confidence -= (len(fix_commits) - 1) * CONFIDENCE_RANGE_REDUCTION_STEP

    if confidence < 0:
      confidence = 0

    tags_with_bug = set()
    for commit in regress_commits:
      tags_with_bug.update(get_tags_with_commits(repo, [commit]))

    tags_with_fix = get_tags_with_commits(repo, fix_commits)

    affected_tags = list(tags_with_bug - tags_with_fix)
    affected_tags.sort()

    affected_commits, affected_ranges = get_affected_range(
        repo, regress_commits, fix_commits)

    if unknown_earlier_revisions:
      # Include the unknown marker in resulting entities.
      regress_commits.insert(0, UNKNOWN_COMMIT)

    return AffectedResult(affected_tags, affected_commits, affected_ranges,
                          regress_commits, fix_commits, confidence)


def get_affected_range(repo, regress_commits, fix_commits):
  """Get affected range."""
  ranges = set()
  commits = set()
  seen_commits = set()

  # Check all branches for cherry picked regress/fix commits.
  for branch in repo.branches.remote:
    ref = 'refs/remotes/' + branch

    # Get the earliest equivalent commit in the regression range.
    equivalent_regress_commit = None
    for regress_commit in regress_commits:
      logging.info('Finding equivalent regress commit to %s in %s',
                   regress_commit, ref)
      equivalent_regress_commit = get_equivalent_commit(repo, ref,
                                                        regress_commit)
      if equivalent_regress_commit:
        break

    if not equivalent_regress_commit:
      continue

    # Get the latest equivalent commit in the fix range.
    equivalent_fix_commit = None
    for fix_commit in fix_commits:
      logging.info('Finding equivalent fix commit to %s in %s', fix_commit, ref)
      equivalent_commit = get_equivalent_commit(repo, ref, fix_commit)
      if equivalent_commit:
        equivalent_fix_commit = equivalent_commit

    ranges.add((equivalent_regress_commit, equivalent_fix_commit))

    last_affected_commits = []
    if equivalent_fix_commit:
      # Last affected commit is the one before the fix.
      last_affected_commits.extend(
          parent.id
          for parent in repo.revparse_single(equivalent_fix_commit).parents)
    else:
      # Not fixed in this branch. Everything is still vulnerabile.
      last_affected_commits.append(repo.revparse_single(ref).id)

    commits.add(equivalent_regress_commit)
    for last_affected_commit in last_affected_commits:
      if (equivalent_regress_commit, last_affected_commit) in seen_commits:
        continue

      seen_commits.add((equivalent_regress_commit, last_affected_commit))
      commits.update(
          get_commit_list(repo, equivalent_regress_commit,
                          last_affected_commit))

  return commits, ranges


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


def get_tags_with_commits(repo, commits):
  """Get tags with a given commit."""
  if not commits:
    return set()

  affected = set()
  logging.info('Getting tags which contain %s', ','.join(commits))

  tags = [
      ref for ref in repo.listall_references() if ref.startswith(TAG_PREFIX)
  ]

  for tag in tags:
    if all(get_equivalent_commit(repo, tag, commit) for commit in commits):
      affected.add(tag[len(TAG_PREFIX):])

  return affected


def get_commit_list(repo, start_commit, end_commit):
  """Get commit list."""
  logging.info('Getting commits %s..%s', start_commit, end_commit)
  try:
    walker = repo.walk(end_commit,
                       pygit2.GIT_SORT_TOPOLOGICAL | pygit2.GIT_SORT_REVERSE)
  except KeyError as e:
    raise ImpactError('Invalid commit.') from e

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


def get_equivalent_commit(repo, to_search, target_commit):
  """Find an equivalent commit at to_search, or None. The equivalent commit can
  be equal to target_commit."""
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
    if not commit.parents:
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


def get_tags(repo_url):
  """Get tags information."""
  with tempfile.TemporaryDirectory() as tmp_dir:
    repo = clone_with_retries(repo_url, tmp_dir)
    tags = [
        ref for ref in repo.listall_references() if ref.startswith(TAG_PREFIX)
    ]

    latest_tag = find_latest_tag(repo, tags)
    return TagsInfo([tag[len(TAG_PREFIX):] for tag in tags], latest_tag)
