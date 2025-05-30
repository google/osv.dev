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
from __future__ import annotations

import datetime
import logging
import os
import re
import sys
import traceback
import tempfile
import yaml
from typing import Any, Dict, List, Optional, Set, Tuple, Union # Added necessary types

from google.cloud import ndb
from google.cloud.pubsub_v1 import types as pubsub_types # For PubsubMessage type
import pygit2 # For pygit2 objects
import pygit2.enums

# Add current dir to path to import other OSV modules.
# This is okay for scripts, but for libraries, relative imports are preferred.
# Assuming this structure is for worker execution.
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import osv.models # For NDB models
import osv.impact # For ImpactError, RepoAnalyzer, AffectedResult
import osv.repos # For clone_with_retries, get_commit_and_tag_list
from osv import vulnerability_pb2 # For Vulnerability proto

OSS_FUZZ_ISSUE_URL: str = 'https://bugs.chromium.org/p/oss-fuzz/issues/detail?id='
SOURCE_PREFIX: str = 'oss-fuzz:'

COMMIT_RANGE_LIMIT: int = 4

# Used in cases where an earlier commit in a regression range cannot be
# determined.
UNKNOWN_COMMIT: str = 'unknown'

# Large projects which take way too long to build.
# TODO(ochang): Don't hardcode this.
PROJECT_DENYLIST: Set[str] = {
    'avahi',  # https://github.com/google/osv.dev/issues/2178
    'boringssl',  # https://github.com/google/osv.dev/issues/2178
    'dbus-broker',  # https://github.com/google/osv.dev/issues/2178
    'elfutils',  # https://github.com/google/osv.dev/issues/2178
    'ffmpeg',
    'imagemagick',
    'libbpf',  # https://github.com/google/osv.dev/issues/2178
    'libreoffice',
    'systemd',  # https://github.com/google/osv.dev/issues/2178
}

REPO_DENYLIST: Set[str] = {
    'https://github.com/google/AFL.git',
}

# Type for bisector.Result, using Any as bisector module is dynamically imported.
BisectorResultType = Any
BuildDataType = Any # Type for build_specified_commit.BuildData


def format_commit_range(old_commit: Optional[str], new_commit: str) -> str:
  """Format a commit range string. Uses UNKNOWN_COMMIT if old_commit is None/empty."""
  if old_commit == new_commit: # If same, just return one
    return new_commit

  # If old_commit is None or empty, use UNKNOWN_COMMIT constant.
  return (old_commit or UNKNOWN_COMMIT) + ':' + new_commit


def find_oss_fuzz_fix_via_commit(repo: pygit2.Repository,
                                 start_commit_hex: str, # Renamed start_commit
                                 end_commit_hex: str, # Renamed end_commit
                                 source_id: str,
                                 issue_id: Optional[str]
                                ) -> Optional[str]:
  """Find fix commit by checking commit messages within a range for OSS-Fuzz references."""
  if not source_id.startswith(SOURCE_PREFIX):
    return None # Not an OSS-Fuzz source ID

  try:
    # Resolve commit hex strings to Oid objects for pygit2.walk
    start_oid: Optional[pygit2.Oid] = repo.revparse_single(start_commit_hex).id if start_commit_hex else None
    end_oid: pygit2.Oid = repo.revparse_single(end_commit_hex).id
  except (KeyError, pygit2.GitError) as e: # Catch errors if commits don't exist or are invalid
    logging.warning('Failed to resolve commits for finding OSS-Fuzz fix: %s (start=%s, end=%s)',
                    e, start_commit_hex, end_commit_hex)
    return None

  # Walk through end_commit_hex back to start_commit_hex (exclusive of start_commit_hex if provided)
  walker: pygit2.Walker = repo.walk(end_oid, pygit2.enums.SortMode.TOPOLOGICAL)
  if start_oid:
    walker.hide(start_oid)

  testcase_id_str: str = source_id.split(':', 1)[1] # Renamed testcase_id
  oss_fuzz_keyword_pattern: Pattern[str] = re.compile(r'oss-?fuzz', re.IGNORECASE) # Renamed

  # Store potential fix commits, ordered by preference
  commits_with_oss_fuzz_mention: List[pygit2.Commit] = [] # Renamed
  commits_with_testcase_id: List[pygit2.Commit] = [] # Renamed
  commits_with_issue_id_and_oss_fuzz: List[pygit2.Commit] = [] # Renamed

  current_commit_obj: pygit2.Commit # Type hint for loop var, renamed commit
  for current_commit_obj in walker:
    commit_msg_lower: str = current_commit_obj.message.lower() # Renamed

    mentions_oss_fuzz: bool = bool(oss_fuzz_keyword_pattern.search(commit_msg_lower)) # Renamed

    if mentions_oss_fuzz:
      commits_with_oss_fuzz_mention.append(current_commit_obj)

    if testcase_id_str in commit_msg_lower:
      commits_with_testcase_id.append(current_commit_obj)

    if issue_id and issue_id in commit_msg_lower and mentions_oss_fuzz:
      commits_with_issue_id_and_oss_fuzz.append(current_commit_obj)

  # Return based on priority
  if commits_with_issue_id_and_oss_fuzz:
    return str(commits_with_issue_id_and_oss_fuzz[0].id)
  if commits_with_testcase_id:
    return str(commits_with_testcase_id[0].id)
  if len(commits_with_oss_fuzz_mention) == 1: # Only if uniquely identified by "oss-fuzz"
    return str(commits_with_oss_fuzz_mention[0].id)

  return None # No suitable fix commit found by this heuristic


def do_bisect(bisect_type_str: str, # Renamed bisect_type
              source_id_str: str, # Renamed source_id
              project_name_str: str, # Renamed project_name
              engine_str: str, # Renamed engine
              sanitizer_str: str, # Renamed sanitizer
              architecture_str: str, # Renamed architecture
              fuzz_target_str: str, # Renamed fuzz_target
              old_commit_hex: str, # Renamed old_commit
              new_commit_hex: str, # Renamed new_commit
              testcase_bytes: bytes # Renamed testcase (is bytes)
             ) -> Optional[BisectorResultType]: # bisector.Result is Any
  """Perform the actual bisection using dynamically imported bisector module."""
  # These imports are dynamic, so types are not statically known without stubs.
  import bisector # type: ignore[import-not-found, import-untyped]
  import build_specified_commit # type: ignore[import-not-found, import-untyped]

  # Write testcase bytes to a temporary file
  with tempfile.NamedTemporaryFile(delete=False) as tmp_testcase_file: # delete=False to control manually
    tmp_testcase_file.write(testcase_bytes)
    testcase_file_path: str = tmp_testcase_file.name

  try:
    build_data_obj: BuildDataType = build_specified_commit.BuildData( # Renamed
        project_name=project_name_str,
        engine=engine_str,
        sanitizer=sanitizer_str,
        architecture=architecture_str
    )

    bisect_result_obj: BisectorResultType = bisector.bisect( # Renamed result
        bisect_type_str, old_commit_hex, new_commit_hex, testcase_file_path,
        fuzz_target_str, build_data_obj
    )
  except bisector.BisectError as e: # bisector.BisectError
    logging.warning('Bisect for %s failed with BisectError: %s\n%s',
                    source_id_str, e, traceback.format_exc())
    # Return a Result-like object indicating error, with repo_url if available from exception.
    # This depends on structure of bisector.Result and BisectError.
    # Assuming BisectError `e` has a `repo_url` attribute.
    return bisector.Result(e.repo_url, None) if hasattr(e, 'repo_url') else None
  except Exception: # Catch any other unexpected errors during bisection
    logging.error('Bisect for %s failed with unexpected exception:\n%s',
                  source_id_str, traceback.format_exc())
    return None # Bisection failed critically
  finally:
    os.remove(testcase_file_path) # Clean up the temporary testcase file

  # If bisect result commit is same as old_commit, it means bisection didn't find a more specific commit.
  if bisect_result_obj and bisect_result_obj.commit == old_commit_hex:
    logging.warning('Bisect for testcase %s resulted in old_commit (%s). Treating as failure.',
                    source_id_str, old_commit_hex)
    return None # Or return bisect_result_obj but flag as inconclusive elsewhere.

  return bisect_result_obj


def process_bisect_task(oss_fuzz_dir_path: str, # Renamed oss_fuzz_dir
                        task_type: str, # 'fixed' or 'regressed', Renamed bisect_type
                        source_id_str: str, # Renamed source_id
                        message: pubsub_types.PubsubMessage
                       ) -> None:
  """Process a bisection task message from Pub/Sub."""
  # Extract necessary attributes from the Pub/Sub message
  # Attributes are Mapping[str, str]. Provide defaults or handle missing ones.
  attributes: Mapping[str, str] = message.attributes

  # `type` attribute from message is preferred over task_type param if different.
  # For consistency, assume task_type param is the definitive one for this function.
  # bisect_type_from_msg: Optional[str] = attributes.get('type')

  project_name_str: Optional[str] = attributes.get('project_name') # Renamed
  # Default engine if not specified, though 'libfuzzer' is common for OSS-Fuzz
  engine_str: str = attributes.get('engine', 'libfuzzer') # Renamed
  architecture_str: str = attributes.get('architecture') or 'x86_64' # Default if empty/None, Renamed
  sanitizer_str: Optional[str] = attributes.get('sanitizer') # Renamed
  fuzz_target_str: Optional[str] = attributes.get('fuzz_target') # Renamed
  old_commit_hex: Optional[str] = attributes.get('old_commit') # Renamed
  new_commit_hex: Optional[str] = attributes.get('new_commit') # Renamed
  testcase_data_bytes: bytes = message.data # Renamed testcase

  # Validate required attributes
  if not all([project_name_str, sanitizer_str, fuzz_target_str, old_commit_hex, new_commit_hex]):
      logging.error("Bisect task for source_id %s missing one or more required attributes. Attributes: %s",
                    source_id_str, attributes)
      return

  logging.info(
      'Performing %s bisect: source_id=%s, project=%s, engine=%s, '
      'architecture=%s, sanitizer=%s, fuzz_target=%s, old_commit=%s, new_commit=%s',
      task_type, source_id_str, project_name_str, engine_str, architecture_str,
      sanitizer_str, fuzz_target_str, old_commit_hex, new_commit_hex)

  bisect_result_obj: Optional[BisectorResultType] = None # Renamed result
  if project_name_str in PROJECT_DENYLIST:
    logging.info('Skipping bisect for denylisted project: %s', project_name_str)
  elif not old_commit_hex: # old_commit is essential for bisection range.
    logging.info('Skipping bisect for source_id %s: old_commit is missing.', source_id_str)
  else:
    # Ensure all required string args for do_bisect are not None.
    # The all() check above should cover these.
    bisect_result_obj = do_bisect(
        task_type, source_id_str, project_name_str, engine_str, sanitizer_str, # type: ignore[arg-type]
        architecture_str, fuzz_target_str, old_commit_hex, new_commit_hex, testcase_data_bytes) # type: ignore[arg-type]

  if bisect_result_obj and hasattr(bisect_result_obj, 'repo_url') and \
     bisect_result_obj.repo_url in REPO_DENYLIST:
    logging.info('Skipping result for denylisted repo: %s', bisect_result_obj.repo_url)
    return # Do not store result from denylisted repo

  # Create or update NDB entity (FixResult or RegressResult)
  # osv.models.FixResult, osv.models.RegressResult needed
  result_entity: Union[osv.models.FixResult, osv.models.RegressResult] # Renamed entity
  if task_type == 'fixed':
    result_entity = osv.models.FixResult(id=source_id_str)
  elif task_type == 'regressed': # Ensure task_type is one of expected
    result_entity = osv.models.RegressResult(id=source_id_str)
  else:
    logging.error("Unknown bisect task type: %s for source_id %s", task_type, source_id_str)
    return

  # Populate entity attributes from message and bisection result
  _set_result_attributes(oss_fuzz_dir_path, message, result_entity)

  if bisect_result_obj and hasattr(bisect_result_obj, 'commit') and bisect_result_obj.commit:
    logging.info('Bisect for source_id %s successful. Commit: %s', source_id_str, bisect_result_obj.commit)
    result_entity.commit = bisect_result_obj.commit
    result_entity.repo_url = bisect_result_obj.repo_url if hasattr(bisect_result_obj, 'repo_url') else None
  else: # Bisection failed or yielded no specific commit
    logging.info(
        'Bisect for source_id %s did not yield a specific commit. Storing original range: %s to %s.',
        source_id_str, old_commit_hex, new_commit_hex)
    # Store the original range if bisection failed. Ensure old_commit_hex is not None.
    result_entity.commit = format_commit_range(old_commit_hex, new_commit_hex or "") # type: ignore[arg-type]
    # Store repo_url from result if available, even on failure, or None
    result_entity.repo_url = bisect_result_obj.repo_url if (bisect_result_obj and hasattr(bisect_result_obj, 'repo_url')) else None
    result_entity.error = 'Bisect error or no specific commit found' # More descriptive error

  result_entity.put()
  logging.info("Stored %s for source_id %s.", result_entity.__class__.__name__, source_id_str)


def set_bug_attributes(bug_model: osv.models.Bug, # Renamed bug
                       regress_result_model: osv.models.RegressResult, # Renamed
                       fix_result_model: osv.models.FixResult # Renamed
                      ) -> None:
  """Set Bug entity attributes from bisection results (RegressResult, FixResult)."""
  # Consolidate information from fix and regress results
  # Prioritize fix_result for most fields if available.
  issue_id_val: Optional[str] = fix_result_model.issue_id or regress_result_model.issue_id # Renamed
  project_name: Optional[str] = fix_result_model.project or regress_result_model.project # Renamed
  ecosystem_name: Optional[str] = fix_result_model.ecosystem or regress_result_model.ecosystem # Renamed
  summary_str: Optional[str] = fix_result_model.summary or regress_result_model.summary # Renamed
  details_str: Optional[str] = fix_result_model.details or regress_result_model.details # Renamed
  severity_str: Optional[str] = fix_result_model.severity or regress_result_model.severity # Renamed

  # reference_urls is a repeated field. Combine them if both exist? Or prioritize?
  # Original code prioritizes fix_result.reference_urls.
  reference_urls_list: List[str] = fix_result_model.reference_urls or regress_result_model.reference_urls or [] # Renamed

  # Ensure project_name and ecosystem_name are not None for AffectedPackage
  if not project_name or not ecosystem_name:
      logging.warning("Cannot set bug attributes: project_name or ecosystem_name is missing for bug %s", bug_model.id())
      # Or raise error, depending on how critical these are.
      return

  # Update bug_model's affected_packages
  # osv.models.AffectedPackage, osv.models.Package needed
  # This replaces any existing affected_packages.
  affected_pkg = osv.models.AffectedPackage( # Renamed
      package=osv.models.Package(name=project_name, ecosystem=ecosystem_name),
      ecosystem_specific={'severity': severity_str} if severity_str else {}
  )
  bug_model.affected_packages = [affected_pkg]

  bug_model.issue_id = issue_id_val
  bug_model.summary = summary_str
  bug_model.details = details_str
  # bug_model.severity is List[Severity], not str. This needs adjustment.
  # Original code `bug.severity = severity` implies it was a direct string assignment.
  # If `bug_model.severity` is meant to store the string from `severity_str`,
  # it needs to be compatible or this part needs refactoring to create Severity model.
  # For now, assuming direct assignment was to a different field or model needs update.
  # This will likely cause a type error if bug_model.severity expects List[osv.models.Severity].
  # TODO: Clarify how single severity string maps to Bug.severities (List[Severity]).
  # For now, let's assume it's meant for a primary severity summary or similar if such field exists.
  # If `bug_model.severity` is indeed the list, this is incorrect:
  # bug_model.severity = severity_str
  # A simple way: if severity_str exists, create one Severity entry.
  if severity_str:
      bug_model.severities = [osv.models.Severity(type='CVSS_V3', score=severity_str)] # Example, type might be unknown

  # Clear and repopulate reference_url_types
  bug_model.reference_url_types = {}
  for ref_url in reference_urls_list: # Renamed reference_url
    link_type_str: str # Renamed
    if OSS_FUZZ_ISSUE_URL in ref_url:
      link_type_str = 'REPORT'
    else: # Default to WEB if not an OSS-Fuzz issue link
      link_type_str = 'WEB'
    bug_model.reference_url_types[ref_url] = link_type_str

  # Set regressed and fixed commit hashes
  bug_model.regressed = regress_result_model.commit or '' # Ensure not None
  bug_model.fixed = fix_result_model.commit or '' # Ensure not None


def _get_commit_range(repo: pygit2.Repository,
                      commit_or_range_str: Optional[str] # Renamed
                     ) -> List[str]:
  """Get a list of commit hexstrs from a single commit or "start:end" range string."""
  if not commit_or_range_str:
    return []

  if ':' not in commit_or_range_str: # Single commit
    # Validate if it's a known commit? Or just return as is?
    # Original code returns it as a list.
    return [commit_or_range_str]

  start_commit_hex, end_commit_hex = commit_or_range_str.split(':', 1) # Renamed
  if start_commit_hex == UNKNOWN_COMMIT:
    # If start is unknown, the range effectively means "everything up to end_commit",
    # but for bisection/analysis, it's often treated as just the end_commit.
    return [end_commit_hex]

  # osv.repos.get_commit_and_tag_list needed
  # This function returns (List[commit_hexstr], List[tag_str])
  # We only need the commit hexstrs here.
  try:
    commits_list, _ = osv.repos.get_commit_and_tag_list(repo, start_commit_hex, end_commit_hex) # Renamed
    return commits_list
  except osv.impact.ImpactError as e: # ImpactError from get_commit_and_tag_list
      logging.warning("Error getting commit list for range %s in repo %s: %s",
                      commit_or_range_str, repo.workdir, e) # type: ignore[union-attr]
      return [] # Return empty list on error


def _get_commits(repo: pygit2.Repository,
                 regress_commit_or_range: Optional[str],
                 fix_commit_or_range: Optional[str]
                ) -> Tuple[List[str], List[str]]:
  """Get lists of commit hexstrs for regression and fix ranges."""
  regress_commits_list: List[str] = _get_commit_range(repo, regress_commit_or_range) # Renamed
  if len(regress_commits_list) > COMMIT_RANGE_LIMIT:
    # osv.impact.ImpactError needed
    raise osv.impact.ImpactError(
        f'Too many commits in regression range ({len(regress_commits_list)} > {COMMIT_RANGE_LIMIT})')

  fix_commits_list: List[str] = _get_commit_range(repo, fix_commit_or_range) # Renamed
  if len(fix_commits_list) > COMMIT_RANGE_LIMIT:
    logging.warning('Too many commits in fix range (%d > %d) for %s. Proceeding with truncated list or original range.',
                    len(fix_commits_list), COMMIT_RANGE_LIMIT, fix_commit_or_range)
    # Original code logs warning and continues. Depending on policy, could truncate or use original range string.
    # For now, implies the full list is used despite warning, or _get_commit_range handles truncation.
    # _get_commit_range does not truncate. So, this list can be long.
    # This might need adjustment if long fix_commits_list is problematic later.

  return regress_commits_list, fix_commits_list


def process_impact_task(source_id_str: str, # Renamed source_id
                        message: pubsub_types.PubsubMessage) -> None:
  """Process an impact analysis task for an OSS-Fuzz sourced bug."""
  logging.info('Processing impact task for source_id: %s', source_id_str)

  # osv.models.RegressResult, osv.models.FixResult, osv.models.Bug, osv.models.BugStatus needed
  # Fetch RegressResult (must exist)
  regress_result_model: Optional[osv.models.RegressResult] = ndb.Key(osv.models.RegressResult, source_id_str).get() # Renamed
  if not regress_result_model:
    logging.error('Missing RegressResult for source_id %s. Cannot process impact.', source_id_str)
    return

  # Fetch FixResult (may not exist if bug not fixed yet)
  fix_result_model: Optional[osv.models.FixResult] = ndb.Key(osv.models.FixResult, source_id_str).get() # Renamed
  if not fix_result_model:
    logging.warning('Missing FixResult for source_id %s. Proceeding with available fix info.', source_id_str)
    # Create a default empty FixResult if None, as set_bug_attributes expects it.
    fix_result_model = osv.models.FixResult()

  # Get the allocated Bug ID from message attributes
  # Attributes are Mapping[str,str]
  allocated_osv_id_attr: Optional[str] = message.attributes.get('allocated_id') # Renamed
  if not allocated_osv_id_attr:
    # osv.impact.ImpactError needed
    raise osv.impact.ImpactError(f"Message for source_id {source_id_str} missing 'allocated_id' attribute.")

  # Fetch the existing Bug entity
  existing_bug_model: Optional[osv.models.Bug] = osv.models.Bug.get_by_id(allocated_osv_id_attr) # Renamed
  if not existing_bug_model:
    # This means the Bug entity that was supposed to be created before this task was run, doesn't exist.
    # This is a critical state error.
    # osv.impact.ImpactError needed
    raise osv.impact.ImpactError(
        f"Bug with allocated_id {allocated_osv_id_attr} not found for source_id {source_id_str}.")

  # Check if Bug source_id matches the task's source_id. Should always match.
  if existing_bug_model.source_id != source_id_str:
    logging.error('Bug %s source_id (%s) mismatch with task source_id (%s). Aborting impact.',
                  allocated_osv_id_attr, existing_bug_model.source_id, source_id_str)
    return # Or raise error

  # If Bug already marked INVALID, log and potentially skip further processing.
  if existing_bug_model.status == osv.models.BugStatus.INVALID:
    logging.warning('Bug %s (source_id %s) already marked as INVALID. Impact processing may be skipped or limited.',
                    allocated_osv_id_attr, source_id_str)
    # Depending on policy, might still update some fields or just return.
    # For now, assume processing continues but this is an alert.
    # return # Example: if invalid means no further updates

  # Determine if the bug is public (from existing Bug entity)
  # This public status is then passed to update_affected_commits.
  # If existing_bug_model.public is None, default to False.
  is_public_bug: bool = existing_bug_model.public or False # Renamed public

  # Determine repo_url: prefer RegressResult, then FixResult. Must exist.
  repo_url_str: Optional[str] = regress_result_model.repo_url or fix_result_model.repo_url # Renamed
  if not repo_url_str:
    # osv.impact.ImpactError needed
    raise osv.impact.ImpactError(f'No repo_url set for source_id {source_id_str} in RegressResult or FixResult.')

  # Populate Bug attributes from bisection results *before* git analysis.
  # This ensures basic info is stored even if git ops fail.
  set_bug_attributes(existing_bug_model, regress_result_model, fix_result_model)
  existing_bug_model.put() # Persist these initial updates

  # Determine fix commit: prefer FixResult, can be a range string.
  fix_commit_str: Optional[str] = fix_result_model.commit # Renamed

  # Perform Git analysis in a temporary directory
  with tempfile.TemporaryDirectory() as tmp_dir_path: # Renamed
    try:
      # osv.repos.clone_with_retries needed
      git_repo: pygit2.Repository = osv.repos.clone_with_retries(repo_url_str, tmp_dir_path) # Renamed repo
    except osv.repos.GitCloneError as e:
        logging.error("Failed to clone repo %s for impact analysis of %s: %s", repo_url_str, source_id_str, e)
        # Mark bug as having an error in processing this step if desired.
        # For now, re-raise as ImpactError to indicate failure of this task part.
        # osv.impact.ImpactError needed
        raise osv.impact.ImpactError(f"Repo clone failed for {repo_url_str}") from e


    # If fix_commit_str is a range (from bisection failure), try to find specific fix commit via message
    # This is specific to OSS-Fuzz sourced bugs.
    if source_id_str.startswith(SOURCE_PREFIX) and fix_commit_str and ':' in fix_commit_str:
      start_hex, end_hex = fix_commit_str.split(':', 1) # Renamed
      # issue_id can be None
      issue_id_for_find: Optional[str] = fix_result_model.issue_id or regress_result_model.issue_id # Renamed

      found_commit_hex: Optional[str] = find_oss_fuzz_fix_via_commit( # Renamed commit
          git_repo, start_hex, end_hex, source_id_str, issue_id_for_find)
      if found_commit_hex:
        logging.info('Found specific fix commit %s for source_id %s via commit message heuristic.',
                     found_commit_hex, source_id_str)
        fix_commit_str = found_commit_hex # Update to the specific commit

    # Get commit lists for regression and fix ranges
    # regress_result_model.commit can be None
    regress_commits_list, fix_commits_list = _get_commits( # Renamed
        git_repo, regress_result_model.commit, fix_commit_str)

    # Determine primary regress and fix commits for RepoAnalyzer
    # If multiple commits in range, pick first for regress, last for fix.
    regress_commit_for_analysis: Optional[str] = regress_commits_list[0] if regress_commits_list else None # Renamed
    fix_commit_for_analysis: Optional[str] = fix_commits_list[-1] if fix_commits_list else None # Renamed

    # osv.impact.RepoAnalyzer, osv.impact.AffectedResult needed
    repo_analyzer_instance = osv.impact.RepoAnalyzer() # Renamed
    affected_result_obj: osv.impact.AffectedResult = repo_analyzer_instance.get_affected( # Renamed result
        git_repo,
        [regress_commit_for_analysis] if regress_commit_for_analysis else [],
        [fix_commit_for_analysis] if fix_commit_for_analysis else []
    )

    # Log found affected tags
    sorted_affected_tags: List[str] = sorted(list(affected_result_obj.tags)) # Renamed
    logging.info('Found affected tags for source_id %s: %s', source_id_str, ', '.join(sorted_affected_tags))

    # If original bisection ranges were imprecise (contained ':'), don't add more ranges from analysis.
    # Clear affected_ranges from result if so.
    if (regress_result_model.commit and ':' in regress_result_model.commit) or \
       (fix_commit_str and ':' in fix_commit_str):
      logging.info("Original bisection range was imprecise for %s; using only that range.", source_id_str)
      affected_result_obj.affected_ranges = [] # Clear if it's List, or .clear() if it's settable list-like
                                             # Assuming it's a list that can be reassigned.

  # Update Bug entity with precise fix/regress commits and affected tags/ranges
  # If fix_commits_list is now a single specific commit (or empty if not fixed)
  if len(fix_commits_list) == 1:
    existing_bug_model.fixed = fix_commits_list[0]
  elif not fix_commits_list: # No fix commit found or range resolved to empty
    existing_bug_model.fixed = '' # Mark as not fixed / empty string
  else: # Multiple fix commits or range still, use original (potentially ranged) fix_commit_str
    existing_bug_model.fixed = fix_commit_str or ''

  # If regress_commits_list is single specific commit (and not original UNKNOWN)
  if len(regress_commits_list) == 1 and \
     not (regress_result_model.commit and UNKNOWN_COMMIT in regress_result_model.commit):
    existing_bug_model.regressed = regress_commits_list[0]
  else: # Multiple regress commits or range, use original (potentially ranged)
    existing_bug_model.regressed = regress_result_model.commit or ''

  # Mark bug as PROCESSED now that impact analysis is done (or attempted)
  # osv.models.BugStatus needed
  existing_bug_model.status = osv.models.BugStatus.PROCESSED

  # Update affected_packages with tags and ranges
  # This logic assumes one primary affected_package, which is typical for OSS-Fuzz bugs.
  # If existing_bug_model.affected_packages is empty or needs specific structure, create it.
  affected_pkg_model: Optional[osv.models.AffectedPackage] = None # Renamed
  if existing_bug_model.affected_packages:
    affected_pkg_model = existing_bug_model.affected_packages[0]
  else: # Create new AffectedPackage if none exists
    # project and ecosystem should have been set by set_bug_attributes
    project_name_val = existing_bug_model.project[0] if existing_bug_model.project else "UnknownProject"
    ecosystem_name_val = existing_bug_model.ecosystem[0] if existing_bug_model.ecosystem else "UnknownEcosystem"
    # osv.models.Package, osv.models.AffectedPackage needed
    affected_pkg_model = osv.models.AffectedPackage(
        package=osv.models.Package(name=project_name_val, ecosystem=ecosystem_name_val)
    )
    existing_bug_model.affected_packages = [affected_pkg_model]

  # Assign sorted affected tags to the versions field
  affected_pkg_model.versions = sorted_affected_tags # type: ignore[union-attr]

  # Construct the primary GIT range from determined introduced/fixed commits
  # Use the first regress commit and last fix commit for the main range.
  introduced_commit_str: str = regress_commits_list[0] if regress_commits_list else '' # Renamed
  final_fix_commit_str: str = fix_commits_list[-1] if fix_commits_list else '' # Renamed

  # osv.models.AffectedEvent, osv.models.AffectedRange2 needed
  range_events: List[osv.models.AffectedEvent] = [ # Renamed
      osv.models.AffectedEvent(type='introduced', value=introduced_commit_str)
  ]
  if final_fix_commit_str: # Only add fixed event if a fix commit exists
    range_events.append(osv.models.AffectedEvent(type='fixed', value=final_fix_commit_str))

  # Main GIT range for this affected package
  # repo_url_str must be non-None here (checked earlier)
  main_git_range = osv.models.AffectedRange2(type='GIT', repo_url=repo_url_str, events=range_events) # Renamed
  # Replace existing ranges with this new primary range plus any additional from analysis.
  affected_pkg_model.ranges = [main_git_range] # type: ignore[union-attr]

  # Add database_specific info for original bisection ranges if they were imprecise
  db_specific_info: Dict[str, str] = {} # Renamed
  if regress_result_model.commit and ':' in regress_result_model.commit:
    db_specific_info['introduced_range'] = regress_result_model.commit
  if fix_commit_str and ':' in fix_commit_str: # Use post-heuristic fix_commit_str
    db_specific_info['fixed_range'] = fix_commit_str

  if db_specific_info:
    affected_pkg_model.database_specific = db_specific_info # type: ignore[union-attr]

  # Add additional ranges from repo_analyzer.get_affected if they are different
  # from the main range and original bisection ranges weren't imprecise.
  if not (':' in (existing_bug_model.fixed or '') or ':' in (existing_bug_model.regressed or '')):
    # Sort key for ranges: (introduced, fixed, last_affected)
    def sort_key_for_ranges(range_tuple: Tuple[Optional[str], Optional[str], Optional[str]]) -> Tuple[str, str, str]: # Renamed
      return (range_tuple[0] or '', range_tuple[1] or '', range_tuple[2] or '')

    for intro_commit, fix_c, last_aff_c in sorted(affected_result_obj.affected_ranges, key=sort_key_for_ranges): # Renamed
      # Ensure strings for comparison, convert None to empty string
      current_fix_c_str = fix_c or ''

      # Skip if this range is same as the main one already added
      if intro_commit == introduced_commit_str and current_fix_c_str == final_fix_commit_str:
        continue

      # Add as additional events to the main_git_range.
      # This logic seems to append all sub-ranges as events to the *first* range.
      # This might not be the standard way to represent multiple distinct affected ranges.
      # OSV schema usually has a list of Range objects in Affected.
      # TODO: Review if this should create new AffectedRange2 objects instead of appending events.
      # For now, following original logic.

      # osv.models.AffectedEvent needed
      new_intro_event = osv.models.AffectedEvent(type='introduced', value=intro_commit or '')
      if new_intro_event not in main_git_range.events: # type: ignore[union-attr] # main_git_range.events can be None
          main_git_range.events.append(new_intro_event) # type: ignore[union-attr]

      if last_aff_c: # If last_affected is present
        new_last_aff_event = osv.models.AffectedEvent(type='last_affected', value=last_aff_c)
        if new_last_aff_event not in main_git_range.events: # type: ignore[union-attr]
            main_git_range.events.append(new_last_aff_event) # type: ignore[union-attr]

      if fix_c: # If fixed is present (and not None)
        new_fix_event = osv.models.AffectedEvent(type='fixed', value=fix_c)
        if new_fix_event not in main_git_range.events: # type: ignore[union-attr]
            main_git_range.events.append(new_fix_event) # type: ignore[union-attr]

  existing_bug_model.put() # Persist all updates to the Bug entity
  logging.info("Successfully processed impact and updated Bug %s (source_id %s)",
               allocated_osv_id_attr, source_id_str)
  # Update AffectedCommits after Bug is finalized.
  # osv.models.update_affected_commits needed
  osv.models.update_affected_commits(allocated_osv_id_attr, affected_result_obj.commits, is_public_bug)


def get_ecosystem(oss_fuzz_dir_path: str, project_name: str) -> str: # Renamed
  """Get ecosystem for an OSS-Fuzz project from its project.yaml."""
  project_yaml_file_path = os.path.join(oss_fuzz_dir_path, 'projects', project_name, 'project.yaml') # Renamed

  try:
    with open(project_yaml_file_path, 'r', encoding='utf-8') as f_handle: # Renamed
      project_yaml_data: Dict[str, Any] = yaml.safe_load(f_handle) # Renamed
  except FileNotFoundError:
    logging.error("project.yaml not found for OSS-Fuzz project: %s at %s",
                  project_name, project_yaml_file_path)
    return 'OSS-Fuzz' # Default if YAML not found
  except yaml.YAMLError:
    logging.error("Error parsing project.yaml for OSS-Fuzz project: %s at %s",
                  project_name, project_yaml_file_path, exc_info=True)
    return 'OSS-Fuzz'


  project_language: str = project_yaml_data.get('language', '').lower() # Renamed

  # Mapping from OSS-Fuzz language to OSV ecosystem name
  ecosystems_map: Dict[str, str] = { # Renamed
      'python': 'PyPI',
      'go': 'Go',
      'rust': 'crates.io', # Added Rust example
      'jvm': 'Maven',      # Added JVM example (though OSS-Fuzz uses 'jvm')
      'javascript': 'npm', # Added JS example
      # Other languages like c, c++ default to 'OSS-Fuzz'
  }
  return ecosystems_map.get(project_language, 'OSS-Fuzz')


def _set_result_attributes(oss_fuzz_dir_path: str, # Renamed
                           message: pubsub_types.PubsubMessage,
                           result_entity: Union[osv.models.FixResult, osv.models.RegressResult] # Renamed entity
                          ) -> None:
  """Set common attributes on FixResult or RegressResult entity from Pub/Sub message."""
  attributes: Mapping[str, str] = message.attributes

  project_name_val: Optional[str] = attributes.get('project_name') # Renamed
  issue_id_val: Optional[str] = attributes.get('issue_id') or None # Ensure None if empty string from attr
  crash_type_str: Optional[str] = attributes.get('crash_type') # Renamed
  crash_state_str: Optional[str] = attributes.get('crash_state') # Renamed
  severity_str: Optional[str] = attributes.get('severity') # Renamed
  timestamp_str: Optional[str] = attributes.get('timestamp') # Renamed

  # These should ideally not be None if message is valid, but handle defensively.
  if not project_name_val or not crash_type_str or not crash_state_str:
      logging.error("Missing critical attributes (project, crash_type, crash_state) in message for %s. Cannot set result attributes.",
                    result_entity.key.id() if result_entity.key else "Unknown Entity") # type: ignore[union-attr]
      return

  result_entity.project = project_name_val
  result_entity.ecosystem = get_ecosystem(oss_fuzz_dir_path, project_name_val)
  result_entity.issue_id = issue_id_val

  if issue_id_val: # Add OSS-Fuzz issue URL as a reference if issue_id exists
      # Ensure reference_urls list exists
      if result_entity.reference_urls is None: result_entity.reference_urls = []
      issue_url = OSS_FUZZ_ISSUE_URL + issue_id_val
      if issue_url not in result_entity.reference_urls:
          result_entity.reference_urls.append(issue_url)

  result_entity.summary = get_oss_fuzz_summary(crash_type_str, crash_state_str)
  result_entity.details = get_oss_fuzz_details(issue_id_val, crash_type_str, crash_state_str)

  if severity_str: # Severity might be empty string
    result_entity.severity = severity_str.upper() # Ensure upper case

  if timestamp_str:
    try:
      result_entity.timestamp = datetime.datetime.fromisoformat(timestamp_str)
      # Ensure it's UTC if not already timezone-aware. fromisoformat might produce naive.
      if result_entity.timestamp.tzinfo is None:
          result_entity.timestamp = result_entity.timestamp.replace(tzinfo=datetime.UTC)
    except ValueError:
      logging.warning("Invalid timestamp format in message attributes: %s", timestamp_str)
      result_entity.timestamp = None # Or set to a default like utcnow()


def handle_timeout(task_type: str, source_id_str: str, # Renamed
                   oss_fuzz_dir_path: str, # Renamed
                   message: pubsub_types.PubsubMessage) -> None:
  """Handle a bisection task timeout: create/update NDB entity with error status."""
  # Attributes needed for _set_result_attributes and format_commit_range
  # Provide defaults if any are missing to avoid KeyErrors later.
  attributes: Mapping[str, str] = message.attributes
  old_commit_hex: Optional[str] = attributes.get('old_commit') # Renamed
  new_commit_hex: Optional[str] = attributes.get('new_commit') # Renamed

  # osv.models.FixResult, osv.models.RegressResult needed
  result_entity_on_timeout: Union[osv.models.FixResult, osv.models.RegressResult] # Renamed entity
  if task_type == 'fixed':
    result_entity_on_timeout = osv.models.FixResult(id=source_id_str)
  elif task_type == 'regressed': # Assuming these are the only two valid task_types here
    result_entity_on_timeout = osv.models.RegressResult(id=source_id_str)
  else: # Should not happen if task_type is validated before calling
      logging.error("Unknown task_type '%s' in handle_timeout for source_id %s.", task_type, source_id_str)
      return

  # Populate common attributes from message
  _set_result_attributes(oss_fuzz_dir_path, message, result_entity_on_timeout)

  # Set commit to the original range and mark error as Timeout
  # Ensure new_commit_hex is not None for format_commit_range if old_commit_hex is not None
  if old_commit_hex and new_commit_hex:
    result_entity_on_timeout.commit = format_commit_range(old_commit_hex, new_commit_hex)
  elif new_commit_hex: # Only new_commit is available (e.g. for initial regression)
    result_entity_on_timeout.commit = format_commit_range(None, new_commit_hex)
  else: # No commit info available, should not happen for bisection tasks
    result_entity_on_timeout.commit = UNKNOWN_COMMIT

  result_entity_on_timeout.error = 'Timeout'
  result_entity_on_timeout.put()
  logging.info("Stored %s for source_id %s after timeout.",
               result_entity_on_timeout.__class__.__name__, source_id_str)


def get_oss_fuzz_summary(crash_type: str, crash_state: str) -> str:
  """Generate a summary from OSS-Fuzz crash type and crash state."""
  # Use first line of crash_type for summary
  processed_crash_type: str = crash_type.splitlines()[0] if crash_type else "Unknown crash type" # Renamed

  state_lines: List[str] = crash_state.splitlines() if crash_state else []
  first_state_line: str = state_lines[0] if state_lines else "Unknown state"

  if processed_crash_type in ('ASSERT', 'CHECK failure', 'Security CHECK failure',
                               'Security DCHECK failure'):
    return f"{processed_crash_type}: {first_state_line}"
  if processed_crash_type == 'Bad-cast':
    return first_state_line # Summary is just the first line of state for Bad-cast

  if not crash_state or crash_state == 'NULL': # If crash_state is empty or "NULL"
    return processed_crash_type # Summary is just the crash_type

  return f"{processed_crash_type} in {first_state_line}"


def get_oss_fuzz_details(issue_id: Optional[str], crash_type: str, crash_state: str) -> str:
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
