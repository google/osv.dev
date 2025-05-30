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
from __future__ import annotations

import argparse
import datetime
import json
import logging
import os
import resource
import shutil
import subprocess
import sys
import threading
import time
from typing import (Any, Callable, Dict, List, Mapping, Optional, Set, Tuple,
                    Type) # Added necessary types

import google.cloud.exceptions
from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud.pubsub_v1 import types as pubsub_types # For PubsubMessage
from google.cloud import storage
from google.cloud.storage import retry as gcs_retry # Alias
from google.cloud.storage.bucket import Bucket # For type hint
from google.cloud.storage.blob import Blob # For type hint


import pygit2 # For pygit2 objects used with osv.repos
import redis # For redis.client.Redis

# Add current dir to path to import other OSV modules.
sys.path.append(os.path.dirname(os.path.realpath(__file__)))

import osv.models # For NDB models
import osv.ecosystems # For ecosystem helpers
import osv.cache # For base Cache class and CacheKey type
import osv.logs # For logging setup
from osv import vulnerability_pb2 # For Vulnerability proto
import osv.repos # For GitRemoteCallback
import osv.sources # For source utility functions
import osv.impact # For AnalyzeResult

# oss_fuzz module specific to this worker, not the top-level osv.oss_fuzz package
import oss_fuzz # Local oss_fuzz.py

DEFAULT_WORK_DIR = '/work'
OSS_FUZZ_GIT_URL = 'https://github.com/google/oss-fuzz.git'
TASK_SUBSCRIPTION = 'tasks' # Pub/Sub subscription name
MAX_LEASE_DURATION = 6 * 60 * 60  # 6 hours (corrected comment)
_TIMEOUT_SECONDS = 60 # For HTTP requests

_ECOSYSTEM_PUSH_TOPICS: Dict[str, str] = {
    'PyPI': 'pypi-bridge',
}

# Thread-local storage for source_id and bug_id for logging context
_state = threading.local()
# Initialize attributes on _state to prevent AttributeError if accessed before set
_state.source_id = None # type: Optional[str]
_state.bug_id = None # type: Optional[str]

# Global NDB client, initialized in __main__
_ndb_client: ndb.Client


class RedisCache(osv.cache.Cache): # osv.cache.Cache needed
  """Redis cache implementation."""

  redis_instance: redis.client.Redis # From redis import Redis

  def __init__(self, host: str, port: int) -> None:
    # Assuming redis.Redis is the correct constructor and type
    self.redis_instance = redis.Redis(host=host, port=port)

  def get(self, key: osv.cache.CacheKey) -> Optional[Any]: # Key type from osv.cache
    try:
      # Key is JSON dumped for Redis storage
      redis_key: str = json.dumps(key)
      value_bytes: Optional[bytes] = self.redis_instance.get(redis_key)
      if value_bytes is None:
        return None
      return json.loads(value_bytes.decode('utf-8')) # Decode bytes then parse JSON
    except (redis.RedisError, json.JSONDecodeError, TypeError) as e:
      logging.warning("RedisCache: Error during get for key %s: %s", key, e)
      # TODO(ochang): Remove this after old cache entries (not JSON dumped) are flushed.
      # This part might be problematic if key itself was not json.dumps(key) before.
      # For now, assuming key is compatible with original logic.
      return None

  def set(self, key: osv.cache.CacheKey, value: Any, ttl_seconds: int) -> Optional[bool]: # Renamed ttl
    try:
      redis_key = json.dumps(key)
      # Value is also JSON dumped for storage
      # Set ex for ttl in seconds. Returns bool or None based on client/success.
      return self.redis_instance.set(redis_key, json.dumps(value), ex=ttl_seconds)
    except (redis.RedisError, TypeError) as e: # TypeError if value is not JSON serializable
      logging.warning("RedisCache: Error during set for key %s: %s", key, e)
      return None


class UpdateConflictError(Exception):
  """Update conflict exception."""


def _setup_logging_extra_info() -> None:
  """Set up extra GCP logging information to include trace and bug IDs."""
  old_factory = logging.getLogRecordFactory()

  def record_factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
    """Insert jsonPayload fields to all logs for source_id, bug_id, thread."""
    record = old_factory(*args, **kwargs)

    # Ensure json_fields attribute exists on the record.
    # Default to empty dict if not present (though it usually should be by now
    # if GCP logging handlers are already attached).
    # For safety, ensure it's a dict.
    if not hasattr(record, 'json_fields') or not isinstance(getattr(record, 'json_fields', None), dict):
      record.json_fields = {} # type: ignore[attr-defined] # Dynamic attribute

    # Add source_id and bug_id from thread-local storage if set.
    # These are Optional[str] on _state.
    source_id_val: Optional[str] = getattr(_state, 'source_id', None)
    if source_id_val:
      record.json_fields['source_id'] = source_id_val # type: ignore[attr-defined]

    bug_id_val: Optional[str] = getattr(_state, 'bug_id', None)
    if bug_id_val:
      record.json_fields['bug_id'] = bug_id_val # type: ignore[attr-defined]

    # Add thread ID for easier log correlation in concurrent scenarios.
    record.json_fields['thread'] = record.thread # type: ignore[attr-defined]
    return record

  logging.setLogRecordFactory(record_factory)


class _PubSubLeaserThread(threading.Thread):
  """Thread that continuously renews the lease for a Pub/Sub message."""

  EXTENSION_TIME_SECONDS: ClassVar[int] = 10 * 60  # 10 minutes.

  _subscriber: pubsub_v1.SubscriberClient
  _subscription: str
  _ack_id: str
  _done_event: threading.Event
  _max_lease_seconds: int

  def __init__(self, subscriber_client: pubsub_v1.SubscriberClient,
               subscription: str, ack_id: str, done_event: threading.Event,
               max_lease_seconds: int) -> None:
    super().__init__()
    self.daemon = True # Thread will exit when main thread exits
    self._subscriber = subscriber_client
    self._subscription = subscription
    self._ack_id = ack_id
    self._done_event = done_event # Event to signal task completion
    self._max_lease_seconds = max_lease_seconds

  def run(self) -> None:
    """Run the leaser thread, renewing ack deadline until task is done or max time reached."""
    # Calculate the absolute time when the lease should finally expire.
    lease_absolute_end_time: float = time.time() + self._max_lease_seconds # Renamed

    while True:
      try:
        current_time_left_seconds: float = lease_absolute_end_time - time.time() # Renamed
        if current_time_left_seconds <= 0:
          logging.warning(
              'Lease for ack_id %s reached maximum lease time of %d seconds. Stopping renewal.',
              self._ack_id, self._max_lease_seconds)
          break # Max lease duration exceeded

        # Determine how long to extend the current lease by.
        # Cannot extend beyond EXTENSION_TIME_SECONDS or remaining total lease time.
        current_extension_seconds: int = int(min(self.EXTENSION_TIME_SECONDS, current_time_left_seconds))
        if current_extension_seconds <=0: # Should not happen if time_left > 0
            break

        logging.info('Renewing lease for ack_id %s by %d seconds.',
                     self._ack_id, current_extension_seconds)
        self._subscriber.modify_ack_deadline(
            subscription=self._subscription,
            ack_ids=[self._ack_id],
            ack_deadline_seconds=current_extension_seconds)

        # Wait before next renewal. Schedule renewal before current extension expires.
        # Wait for half the extension time, or until done event is set, or until total time left if shorter.
        wait_interval_seconds: float = min(current_time_left_seconds, float(current_extension_seconds) / 2) # Renamed

        if self._done_event.wait(timeout=wait_interval_seconds):
          logging.info('Task associated with ack_id %s completed. Stopping lease renewal.', self._ack_id)
          break # Task is done, stop renewing
      except Exception: # Catch any exception during lease renewal
        logging.exception('PubSubLeaserThread failed for ack_id %s:', self._ack_id)
        # Thread will exit due to unhandled exception. Main task might continue if not waiting on this.
        # Or, could try to recover/retry, but Pub/Sub lease might be lost.
        break


def clean_artifacts(oss_fuzz_dir_path: str) -> None: # Renamed oss_fuzz_dir
  """Clean build artifacts from previous OSS-Fuzz runs."""
  build_dir_path = os.path.join(oss_fuzz_dir_path, 'build') # Renamed
  if os.path.exists(build_dir_path):
    logging.info("Cleaning OSS-Fuzz build directory: %s", build_dir_path)
    shutil.rmtree(build_dir_path, ignore_errors=True) # ignore_errors helps if some files are locked


def mark_bug_invalid(message: pubsub_types.PubsubMessage) -> None: # Use specific PubsubMessage type
  """Mark a bug and its associated AffectedCommits as INVALID and withdrawn."""
  source_id_val: Optional[str] = get_source_id(message) # Renamed
  if not source_id_val:
      logging.error("Cannot mark bug invalid: source_id missing from message attributes: %s", message.attributes)
      return

  # osv.models.Bug, osv.models.BugStatus needed
  bug_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query(osv.models.Bug.source_id == source_id_val)

  bug_to_invalidate: Optional[osv.models.Bug] = None # To store the bug if found
  # Assuming source_id is unique enough that .get() or a loop for one is fine.
  # If multiple bugs could share a source_id (not typical), this logic might need adjustment.
  for bug_item in bug_query: # Renamed bug
    bug_to_invalidate = bug_item
    bug_to_invalidate.withdrawn = datetime.datetime.now(datetime.UTC)
    bug_to_invalidate.status = osv.models.BugStatus.INVALID # Direct enum member assignment
    bug_to_invalidate.put()
    logging.info("Marked Bug %s (source_id: %s) as INVALID and withdrawn.",
                 bug_to_invalidate.id(), source_id_val)

    # Make associated AffectedCommits entities no longer public (or delete them)
    # Original code sets public=False on AffectedCommits.
    # osv.models.delete_affected_commits is more about removing them.
    # Let's follow original intent: mark public=False or handle as per osv.delete_affected_commits.
    # The original code was `osv.delete_affected_commits(bug.key.id())`
    # This implies that for invalid bugs, their commit lists are removed.
    if bug_to_invalidate.key: # Ensure key is present
        osv.models.delete_affected_commits(bug_to_invalidate.key.id()) # type: ignore[union-attr]
        logging.info("Deleted AffectedCommits for Bug ID: %s", bug_to_invalidate.key.id()) # type: ignore[union-attr]
    break # Assuming only one bug per source_id

  if not bug_to_invalidate:
      logging.warning("No Bug found with source_id %s to mark as invalid.", source_id_val)


def get_source_id(message: pubsub_types.PubsubMessage) -> Optional[str]:
  """Get source_id from Pub/Sub message attributes.
     Prefers 'source_id', falls back to 'testcase_id' (prefixed for OSS-Fuzz).
  """
  attributes: Mapping[str, str] = message.attributes # Attributes are Mapping[str, str]

  source_id_val: Optional[str] = attributes.get('source_id') # Renamed
  if source_id_val:
    return source_id_val

  testcase_id_val: Optional[str] = attributes.get('testcase_id') # Renamed
  if testcase_id_val:
    # oss_fuzz.SOURCE_PREFIX should be from the local oss_fuzz.py module
    return oss_fuzz.SOURCE_PREFIX + testcase_id_val

  return None # Neither relevant attribute found


def add_fix_information(vulnerability: vulnerability_pb2.Vulnerability,
                        fix_result_model: osv.models.FixResult # Renamed fix_result
                       ) -> bool:
  """Add fix information (commit) to a Vulnerability protobuf message.
     Modifies `vulnerability` in-place. Returns True if changes were made.
  """
  # database_specific is a map field, can be accessed like a dict
  db_specific_updates: Dict[str, str] = {} # Renamed database_specific

  fix_commit_hash: str = fix_result_model.commit or "" # Renamed fix_commit, ensure not None

  # If FixResult.commit contains ':', it's a range "introduced:fixed".
  # The part after ':' is the actual fixing commit hash.
  # The full range is stored in database_specific.fixed_range.
  if ':' in fix_commit_hash:
    db_specific_updates['fixed_range'] = fix_commit_hash
    fix_commit_hash = fix_commit_hash.split(':', 1)[1] # Get the part after ':'

  if not fix_commit_hash: # No valid fix commit hash to add
      return False

  made_changes: bool = False # Renamed has_changes

  affected_pkg_proto: vulnerability_pb2.Affected # Type hint for loop var, renamed
  for affected_pkg_proto in vulnerability.affected:
    added_fix_to_this_package: bool = False # Renamed added_fix

    # Collect unique repo URLs from GIT ranges in this Affected message
    # vulnerability_pb2.Range needed
    git_repo_urls: Set[str] = set() # Renamed repos
    for affected_range_proto in affected_pkg_proto.ranges: # Renamed
      if affected_range_proto.type == vulnerability_pb2.Range.Type.GIT: # Use enum value
        if affected_range_proto.repo: # Ensure repo URL is not empty
            git_repo_urls.add(affected_range_proto.repo)

    # Iterate through GIT ranges again to add the fix event
    for affected_range_proto in affected_pkg_proto.ranges:
      if affected_range_proto.type != vulnerability_pb2.Range.Type.GIT:
        continue

      # Add fix if:
      # 1. The FixResult's repo_url matches this range's repo, OR
      # 2. There's only one unique repo URL across all GIT ranges for this package
      #    (implying the fix must belong to this repo).
      # AND
      # 3. This range does not already contain this specific fix_commit_hash.
      repo_url_matches_or_is_singular: bool = (
          (fix_result_model.repo_url == affected_range_proto.repo) or \
          (len(git_repo_urls) == 1 and affected_range_proto.repo in git_repo_urls) # Check if the single repo is this one
      )

      fix_event_already_exists = any(
          event.fixed == fix_commit_hash for event in affected_range_proto.events
      )

      if repo_url_matches_or_is_singular and not fix_event_already_exists:
        added_fix_to_this_package = True
        made_changes = True
        # Add new "fixed" event to this range
        new_event = affected_range_proto.events.add() # Add new Event message
        new_event.fixed = fix_commit_hash

        # Per original logic, clear existing versions list if a fix is added to a range.
        # This forces re-computation of affected versions from ranges.
        del affected_pkg_proto.versions[:] # Clear field

    if added_fix_to_this_package and db_specific_updates:
      # If fix range was stored (e.g. "intro_hash:fix_hash"), add to database_specific.
      # The database_specific field in Affected proto is Struct.
      # Update works like dict.update for Struct.
      affected_pkg_proto.database_specific.update(db_specific_updates)

  return made_changes


# TODO(ochang): Remove this function once GHSA's encoding is fixed.
def fix_invalid_ghsa(vulnerability: vulnerability_pb2.Vulnerability) -> bool:
  """Attempt to fix an invalid GHSA entry by removing problematic ranges/versions.
     Returns True if the entry is now valid or was already valid, False if unfixable.
  """
  # Map: (ecosystem, name) -> {'has_single_introduced': bool, 'has_fixed': bool}
  package_fix_details: Dict[Tuple[str, str], Dict[str, bool]] = {} # Renamed packages, details

  for affected_proto in vulnerability.affected: # Renamed affected
    # Ensure package info exists
    if not affected_proto.HasField('package'): continue

    pkg_key = (affected_proto.package.ecosystem, affected_proto.package.name)
    current_pkg_details = package_fix_details.setdefault(
        pkg_key, {'has_single_introduced': False, 'has_fixed': False}) # Renamed details

    has_bad_equals_version_encoding: bool = False # Renamed
    # Check for specific bad encoding: single "introduced" event in a range,
    # and versions list has that same "introduced" value as the only version.
    # See https://github.com/github/advisory-database/issues/59
    for range_proto in affected_proto.ranges: # Renamed affected_range
      if len(range_proto.events) == 1 and range_proto.events[0].HasField('introduced'):
        current_pkg_details['has_single_introduced'] = True
        # Check if versions list matches this specific bad pattern
        if len(affected_proto.versions) == 1 and \
           affected_proto.versions[0] == range_proto.events[0].introduced:
          has_bad_equals_version_encoding = True

      # Check if any range has a "fixed" event
      for event_proto in range_proto.events: # Renamed event
        if event_proto.HasField('fixed'):
          current_pkg_details['has_fixed'] = True

    if has_bad_equals_version_encoding:
      # If this bad encoding is found, try to fix it only if it's the sole range.
      if len(affected_proto.ranges) == 1:
        logging.info('Attempting to fix GHSA encoding: Removing bad range from %s for package %s/%s',
                     vulnerability.id, pkg_key[0], pkg_key[1])
        del affected_proto.ranges[:] # Remove the problematic range
        # Versions list was already tied to this bad range, so it's implicitly handled
        # by the fact that `analyze` will re-evaluate versions from (now empty) ranges.
      else:
        # Multiple ranges exist, and one has this bad pattern. Unfixable by simple removal.
        logging.warning("Cannot fix GHSA encoding for %s (package %s/%s): bad 'equals' version with multiple ranges.",
                        vulnerability.id, pkg_key[0], pkg_key[1])
        return False

  # Second pass: check for another type of bad encoding across all packages.
  # If a package has some ranges with only "introduced" AND other ranges with "fixed",
  # this is considered problematic by original logic.
  for details_val in package_fix_details.values(): # Renamed details
    if details_val['has_single_introduced'] and details_val['has_fixed']:
      logging.warning("Invalid GHSA encoding for %s: Package has both 'introduced-only' ranges and 'fixed' events.",
                      vulnerability.id)
      return False

  return True # Valid or successfully fixed


def maybe_normalize_package_names(vulnerability: vulnerability_pb2.Vulnerability
                                 ) -> vulnerability_pb2.Vulnerability:
  """Normalize package names within the vulnerability as necessary. Modifies in-place."""
  for affected_proto in vulnerability.affected: # Renamed affected
    if not affected_proto.HasField('package') or not affected_proto.package.ecosystem:
      continue # Skip if no ecosystem to determine normalization rules

    # osv.ecosystems.maybe_normalize_package_names needed
    affected_proto.package.name = osv.ecosystems.maybe_normalize_package_names(
        affected_proto.package.name, affected_proto.package.ecosystem)
  return vulnerability


def filter_unsupported_ecosystems(vulnerability: vulnerability_pb2.Vulnerability) -> None:
  """Remove unsupported ecosystems from vulnerability. Modifies in-place."""
  supported_affected_entries: List[vulnerability_pb2.Affected] = [] # Renamed filtered
  for affected_proto in vulnerability.affected: # Renamed affected
    # Keep if no package info (e.g. CVE-converted OSV records for general software)
    if not affected_proto.HasField('package'):
      supported_affected_entries.append(affected_proto)
    # Keep if ecosystem is known/supported
    elif osv.ecosystems.get(affected_proto.package.ecosystem): # osv.ecosystems
      supported_affected_entries.append(affected_proto)
    else: # Log and discard unsupported ecosystem entry
      logging.warning('%s contains unsupported ecosystem "%s". Entry will be filtered.',
                      vulnerability.id, affected_proto.package.ecosystem)

  del vulnerability.affected[:] # Clear original list
  vulnerability.affected.extend(supported_affected_entries) # Add back filtered list


class TaskRunner:
  """Task runner for processing Pub/Sub messages."""
  _ndb_client: ndb.Client
  _oss_fuzz_dir: str
  _work_dir: str
  _sources_dir: str
  _ssh_key_public_path: Optional[str]
  _ssh_key_private_path: Optional[str]
  _publisher: pubsub_v1.PublisherClient
  _tasks_topic: str


  def __init__(self, ndb_client_instance: ndb.Client, # Renamed
               oss_fuzz_dir_path: str, # Renamed
               work_dir_path: str, # Renamed
               ssh_key_public_path_val: Optional[str], # Renamed
               ssh_key_private_path_val: Optional[str] # Renamed
              ) -> None:
    self._ndb_client = ndb_client_instance
    self._oss_fuzz_dir = oss_fuzz_dir_path
    self._work_dir = work_dir_path
    self._sources_dir = os.path.join(self._work_dir, 'sources')
    self._ssh_key_public_path = ssh_key_public_path_val
    self._ssh_key_private_path = ssh_key_private_path_val
    os.makedirs(self._sources_dir, exist_ok=True)

    self._publisher = pubsub_v1.PublisherClient()
    # GOOGLE_CLOUD_PROJECT should be set in env.
    project_id = os.environ['GOOGLE_CLOUD_PROJECT']
    self._tasks_topic = self._publisher.topic_path(project_id, _TASKS_TOPIC)
    logging.info('TaskRunner initialized. Work dir: %s, Sources dir: %s',
                 self._work_dir, self._sources_dir)


  def _git_callbacks(self, source_repo: osv.models.SourceRepository
                    ) -> Optional[osv.repos.GitRemoteCallback]: # osv.repos
    """Get git auth callbacks if SSH keys are configured."""
    if not source_repo.repo_username or \
       not self._ssh_key_public_path or \
       not self._ssh_key_private_path:
      return None # SSH keys not available or not needed by repo
    # osv.repos.GitRemoteCallback needed
    return osv.repos.GitRemoteCallback(source_repo.repo_username,
                                       self._ssh_key_public_path,
                                       self._ssh_key_private_path)

  def _source_update(self, message: pubsub_types.PubsubMessage) -> None:
    """Process a source update task message."""
    # Message attributes are str, ensure correct type conversion if needed.
    source_name: Optional[str] = message.attributes.get('source') # Renamed source
    repo_file_path: Optional[str] = message.attributes.get('path') # Renamed path
    original_content_sha256: Optional[str] = message.attributes.get('original_sha256') # Renamed
    is_deleted: bool = message.attributes.get('deleted', 'false').lower() == 'true' # Renamed, default 'false'

    if not source_name or not repo_file_path: # original_sha256 can be empty for new files
        logging.error("Source update message missing 'source' or 'path' attribute: %s", message.attributes)
        return

    # osv.models.get_source_repository needed
    source_repo_model: Optional[osv.models.SourceRepository] = osv.models.get_source_repository(source_name) # Renamed
    if source_repo_model is None:
      # This might happen if a source was deleted but messages are still in flight.
      logging.error('Failed to get source repository: %s. Message may be stale.', source_name)
      # Consider whether to raise, nack, or just log and ack.
      # For now, log and return, implying message will be acked by caller.
      return # Cannot proceed without source_repo_model definition.

    # Current local pygit2.Repository checkout, None for non-Git sources
    local_git_repo: Optional[pygit2.Repository] = None # Renamed repo

    # List of vulnerabilities parsed from the file/blob/API response
    parsed_vulnerabilities: List[vulnerability_pb2.Vulnerability] # Renamed

    current_content_sha256: str # Renamed

    # osv.models.SourceRepositoryType needed
    if source_repo_model.type == osv.models.SourceRepositoryType.GIT:
      try:
        local_git_repo = osv.repos.ensure_updated_checkout( # osv.repos
            source_repo_model.repo_url, # Must be non-None for GIT type
            os.path.join(self._sources_dir, source_name),
            git_callbacks=self._git_callbacks(source_repo_model),
            branch=source_repo_model.repo_branch # Can be None
        )
      except osv.repos.GitCloneError as e: # osv.repos
          logging.error("Failed to checkout repo for source %s, path %s: %s", source_name, repo_file_path, e)
          return # Cannot proceed

      # Full path to the vulnerability file in the local git checkout
      # osv.sources.repo_path needed
      vuln_full_path = os.path.join(sources.repo_path(local_git_repo), repo_file_path) # Renamed

      if not os.path.exists(vuln_full_path):
        logging.info('File %s was deleted from repo %s.', vuln_full_path, source_name)
        if is_deleted: # Deletion was expected
          self._handle_deleted(source_repo_model, repo_file_path)
        # If not expected (e.g. file moved/deleted unexpectedly), it's logged.
        # Update task might be for a now-deleted file due to race; this is okay.
        return

      if is_deleted: # Deletion requested, but file still exists. This is a conflict/problem.
        logging.warning('Deletion request for %s in %s, but file still exists. Aborting deletion handling.',
                        repo_file_path, source_name)
        return

      try:
        # osv.sources.parse_vulnerabilities needed
        parsed_vulnerabilities = sources.parse_vulnerabilities(
            vuln_full_path, key_path=source_repo_model.key_path,
            strict=source_repo_model.strict_validation and self._strict_validation)
      except Exception: # Catch any parsing error
        logging.exception('Failed to parse vulnerability from git source: %s, path: %s',
                          source_name, vuln_full_path)
        return

      # osv.sources.sha256 needed
      current_content_sha256 = sources.sha256(vuln_full_path)

    elif source_repo_model.type == osv.models.SourceRepositoryType.BUCKET:
      if is_deleted: # Deletion message for a bucket source
        self._handle_deleted(source_repo_model, repo_file_path)
        return

      # Download blob content from GCS
      storage_client_instance = storage.Client() # Renamed
      if not source_repo_model.bucket: # Should be validated by importer.SourceRepository
          logging.error("Bucket not configured for source %s", source_name)
          return

      bucket_obj: Bucket = storage_client_instance.bucket(source_repo_model.bucket) # Renamed
      try:
        # Ensure repo_file_path is not None for blob name
        blob_obj: Optional[Blob] = bucket_obj.get_blob(repo_file_path) # Renamed
        if not blob_obj: # Blob not found
            logging.error('GCS path %s/%s does not exist.', source_repo_model.bucket, repo_file_path)
            return
        blob_bytes_content: bytes = blob_obj.download_as_bytes(retry=gcs_retry.DEFAULT_RETRY) # Renamed
      except google.cloud.exceptions.NotFound: # More specific exception
        logging.error('GCS path %s/%s does not exist (NotFound).', source_repo_model.bucket, repo_file_path)
        return
      except Exception: # Other GCS errors
        logging.exception('Failed to download GCS blob: %s/%s', source_repo_model.bucket, repo_file_path)
        return

      # osv.sources.sha256_bytes needed
      current_content_sha256 = sources.sha256_bytes(blob_bytes_content)
      try:
        # osv.sources.parse_vulnerabilities_from_data needed
        # Ensure repo_file_path is not None for os.path.splitext
        file_extension = os.path.splitext(repo_file_path)[1]
        parsed_vulnerabilities = sources.parse_vulnerabilities_from_data(
            blob_bytes_content.decode('utf-8'), # Expects string
            extension=file_extension,
            key_path=source_repo_model.key_path,
            strict=source_repo_model.strict_validation and self._strict_validation
        )
      except Exception:
        logging.exception('Failed to parse vulnerability from GCS blob: %s, path: %s',
                          source_name, repo_file_path)
        return

    elif source_repo_model.type == osv.models.SourceRepositoryType.REST_ENDPOINT:
      if is_deleted: # Deletion for REST not fully supported here yet.
          logging.warning("Deletion via REST endpoint not fully implemented for %s, path %s.",
                          source_name, repo_file_path)
          # self._handle_deleted(source_repo_model, repo_file_path) might be called if applicable.
          return

      # Fetch from REST API
      # Ensure source_repo_model.link and repo_file_path (as part of URL) are valid.
      if not source_repo_model.link or not repo_file_path:
          logging.error("REST source %s misconfigured: link or path is empty.", source_name)
          return

      # Assuming repo_file_path is the ID + extension for the URL.
      # This might need adjustment based on actual REST API structure.
      rest_url = source_repo_model.link + repo_file_path
      try:
          http_response = requests.get(rest_url, timeout=_TIMEOUT_SECONDS) # Renamed request
          http_response.raise_for_status() # Check for HTTP errors
          # Try to parse as JSON, then into Vulnerability proto
          # osv.sources.parse_vulnerability_from_dict needed
          parsed_vulnerabilities = [sources.parse_vulnerability_from_dict(http_response.json(),
                                    key_path=source_repo_model.key_path,
                                    strict=source_repo_model.strict_validation and self._strict_validation
                                   )]
          current_content_sha256 = sources.sha256_bytes(http_response.text.encode('utf-8')) # osv.sources
      except requests.exceptions.RequestException as e:
          logging.exception("Failed to fetch from REST API %s: %s", rest_url, e)
          return
      except (json.JSONDecodeError, Exception) as e: # Catch parsing or other errors
          logging.exception("Failed to parse vulnerability from REST API %s (URL: %s): %s",
                            source_name, rest_url, e)
          return
    else:
      logging.error('Unsupported SourceRepository type for source %s: %s',
                    source_name, source_repo_model.type)
      return # Should not happen if source_repo is validated

    # Check if content has changed since task was scheduled.
    if current_content_sha256 != original_content_sha256 and original_content_sha256 is not None:
      logging.warning(
          'SHA256 of %s in source %s no longer matches expected (expected=%s vs current=%s). Aborting update.',
          repo_file_path, source_name, original_content_sha256, current_content_sha256)
      return

    # Process each vulnerability found in the file/blob/response.
    # Typically one, but format allows multiple.
    for vuln_proto in parsed_vulnerabilities: # Renamed vulnerability
      # Pass local_git_repo (which is pygit2.Repository or None)
      self._do_update(source_repo_model, local_git_repo, vuln_proto,
                      repo_file_path, original_content_sha256 or "") # Ensure original_sha256 is str

  def _handle_deleted(self, source_repo: osv.models.SourceRepository, vuln_file_path: str) -> None: # Renamed
    """Handle existing bugs that have been subsequently deleted at their source."""
    # Infer Bug ID from filename (path).
    vuln_id_str: str = os.path.splitext(os.path.basename(vuln_file_path))[0] # Renamed

    # osv.models.Bug needed
    bug_to_withdraw: Optional[osv.models.Bug] = osv.models.Bug.get_by_id(vuln_id_str) # Renamed
    if not bug_to_withdraw:
      logging.warning('Bug ID %s (from deleted path %s) not found in NDB. No action needed.',
                    vuln_id_str, vuln_file_path)
      return

    # Verify that the source_id in the Bug record matches the one being deleted.
    # This prevents accidental deletion if ID matches but source differs.
    # osv.sources.source_path, osv.sources.parse_source_id needed
    # Bug.source_id is "SOURCE_NAME:PATH_IN_SOURCE"
    # We need to ensure that PATH_IN_SOURCE matches vuln_file_path.
    expected_source_id_path_part = sources.source_path(source_repo, bug_to_withdraw) # This might be complex
    # A simpler check: ensure bug's source name matches, and its stored path part matches.
    # This requires bug.source_id to be consistently `source_repo.name + ':' + vuln_file_path_relative_to_source_root`

    # For now, assume if bug.id matches filename, and source matches, it's the one.
    # A more robust check might involve comparing source_id directly if it's stored that way.
    # The original code was `osv.source_path(source_repo, bug)` vs `vuln_path`.
    # `osv.source_path` is complex. A direct check on `bug.source_id` might be better if format is fixed.
    # If bug.source_id is `source_repo.name + ":" + vuln_file_path`
    expected_source_id_str = f"{source_repo.name}:{vuln_file_path}"
    if bug_to_withdraw.source_id != expected_source_id_str:
      logging.error(
          'Deletion request for path %s (Bug ID %s) in source %s, '
          'but DB record source_id (%s) does not match. Aborting deletion.',
          vuln_file_path, vuln_id_str, source_repo.name, bug_to_withdraw.source_id)
      return

    logging.info('Marking Bug ID %s (from path %s) as INVALID and withdrawn due to source deletion.',
                 vuln_id_str, vuln_file_path)
    # osv.models.BugStatus needed
    bug_to_withdraw.status = osv.models.BugStatus.INVALID
    bug_to_withdraw.withdrawn = datetime.datetime.now(datetime.UTC)
    bug_to_withdraw.put()
    # Delete associated AffectedCommits as well
    # osv.models.delete_affected_commits needed
    if bug_to_withdraw.key: # Ensure key exists
        osv.models.delete_affected_commits(bug_to_withdraw.key.id()) # type: ignore[union-attr]


  def _push_new_ranges_and_versions(self, source_repo: osv.models.SourceRepository,
                                    repo: pygit2.Repository,
                                    vulnerability: vulnerability_pb2.Vulnerability,
                                    output_file_path: str, # Renamed output_path
                                    original_sha256: str) -> bool:
    """Pushes new ranges and versions back to a Git repository if source is editable."""
    # osv.models.write_vulnerability, osv.repos.push_source_changes needed
    osv.models.write_vulnerability(
        vulnerability, output_file_path, key_path=source_repo.key_path)

    repo.index.add_all() # Stage all changes (including the updated file)
    # Check if there are actual changes to commit before proceeding
    if not repo.index.diff_to_tree(repo.head.peel(pygit2.Tree)): # type: ignore[union-attr] # head can be None
        logging.info("No effective changes to commit for %s in %s. Skipping push.",
                     vulnerability.id, source_repo.name)
        return True # Treat as success, no push needed

    # osv.repos.push_source_changes needed
    return osv.repos.push_source_changes(
        repo,
        f'Update {vulnerability.id}', # Commit message
        self._git_callbacks(source_repo), # Git auth callbacks
        expected_hashes={ # For optimistic locking: path relative to repo root -> old hash
            os.path.relpath(output_file_path, repo.workdir): original_sha256, # type: ignore[union-attr]
        })


  def _analyze_vulnerability(self, source_repo: osv.models.SourceRepository,
                             repo: Optional[pygit2.Repository], # Can be None for non-Git sources
                             vulnerability: vulnerability_pb2.Vulnerability,
                             file_path_in_source: str, # Renamed path
                             original_sha256: str) -> osv.impact.AnalyzeResult: # osv.impact
    """Analyze vulnerability, potentially update it with new ranges/versions, and push if changed & editable."""
    # Add OSS-Fuzz fix information if applicable (Bug exists and has FixResult)
    # This part seems specific to OSS-Fuzz related bugs or bugs that might have FixResult.
    # osv.models.Bug, osv.models.FixResult needed
    added_fix_info_flag: bool = False # Renamed
    # Check if a Bug entity exists for this vulnerability ID
    bug_model_for_fix: Optional[osv.models.Bug] = osv.models.Bug.get_by_id(vulnerability.id) # Renamed
    if bug_model_for_fix and bug_model_for_fix.source_id: # Ensure source_id exists for FixResult key
      # Try to get FixResult using the bug's source_id
      fix_result_model: Optional[osv.models.FixResult] = osv.models.FixResult.get_by_id(bug_model_for_fix.source_id) # Renamed
      if fix_result_model:
        added_fix_info_flag = add_fix_information(vulnerability, fix_result_model)

    # Perform impact analysis (e.g., find affected commits from ranges)
    # osv.impact.analyze needed
    analysis_result: osv.impact.AnalyzeResult = osv.impact.analyze( # Renamed result
        vulnerability,
        analyze_git=not source_repo.ignore_git, # Control if git analysis is done
        # checkout_path is not passed here, analyze will clone if needed for GIT ranges.
        detect_cherrypicks=source_repo.detect_cherrypicks,
        versions_from_repo=source_repo.versions_from_repo,
        consider_all_branches=source_repo.consider_all_branches
    )

    # If analysis or added fix info resulted in changes, and repo is editable Git source
    if (analysis_result.has_changes or added_fix_info_flag):
      if source_repo.editable and source_repo.type == osv.models.SourceRepositoryType.GIT and repo:
        # output_path needs to be the full local path in the checkout
        # osv.sources.repo_path needed
        full_output_path = os.path.join(sources.repo_path(repo), file_path_in_source) # Renamed

        if self._push_new_ranges_and_versions(source_repo, repo, vulnerability,
                                              full_output_path, original_sha256):
          logging.info('Successfully updated and pushed changes for vulnerability %s in %s.',
                       vulnerability.id, source_repo.name)
        else:
          # Push failed (e.g., conflict, auth error).
          logging.warning('Failed to push updated ranges/versions for %s due to conflicts or error. Discarding changes.',
                          vulnerability.id)
          raise UpdateConflictError(f"Failed to push changes for {vulnerability.id} due to conflict.")
      elif source_repo.editable: # Editable but not GIT (e.g. bucket, REST) - not supported by current push logic
          logging.warning("Source %s is editable but not GIT type. Auto-updates via push not supported.", source_repo.name)
          # If it's an editable bucket/REST, changes to `vulnerability` proto are in memory
          # but won't be written back to the source by this function.
          # The main update logic in _do_update will handle NDB storage.
          # For non-Git editable sources, an alternative update mechanism for the source itself would be needed.

    return analysis_result # Return analysis result (commits found, if changes were made to proto by analyze)


  def _do_update(self, source_repo: osv.models.SourceRepository,
                 repo_checkout: Optional[pygit2.Repository], # Renamed repo
                 vulnerability: vulnerability_pb2.Vulnerability,
                 relative_file_path: str, # Renamed relative_path
                 original_sha256: str) -> None:
    """Process updates on a single vulnerability: analyze, update NDB, notify."""
    _state.bug_id = vulnerability.id # Set thread-local bug_id for logging
    logging.info('Processing update for vulnerability %s from source %s, path %s',
                 vulnerability.id, source_repo.name, relative_file_path)

    # Pre-processing: normalize names, fix known GHSA issues, filter unsupported ecosystems
    processed_vulnerability = maybe_normalize_package_names(vulnerability) # Renamed
    if source_repo.name == 'ghsa' and not fix_invalid_ghsa(processed_vulnerability):
      logging.warning('GHSA entry %s has an unfixable encoding error. Skipping update.', processed_vulnerability.id)
      self._record_quality_finding(source_repo.name, processed_vulnerability.id, osv.models.ImportFindings.INVALID_RECORD)
      return
    filter_unsupported_ecosystems(processed_vulnerability)

    # Store original modified date from the source data before analysis potentially changes it
    # Ensure .modified is present and has seconds/nanos
    source_modified_dt: Optional[datetime.datetime] = None # Renamed
    if processed_vulnerability.modified and \
       (processed_vulnerability.modified.seconds or processed_vulnerability.modified.nanos):
      source_modified_dt = processed_vulnerability.modified.ToDatetime().replace(tzinfo=datetime.UTC)

    analysis_result_obj: osv.impact.AnalyzeResult # Renamed result
    try:
      analysis_result_obj = self._analyze_vulnerability(
          source_repo, repo_checkout, processed_vulnerability,
          relative_file_path, original_sha256)
    except UpdateConflictError:
      # Analyze tried to push changes but failed (e.g. Git conflict).
      # Error already logged by _analyze_vulnerability. Discard NDB update for this vuln.
      return
    except Exception: # Catch any other error during analysis
        logging.exception("Error during _analyze_vulnerability for %s", vulnerability.id)
        self._record_quality_finding(source_repo.name, vulnerability.id, osv.models.ImportFindings.INVALID_RECORD) # Generic error
        return


    # Update NDB Bug entity
    # osv.models.Bug, osv.models.BugStatus, osv.models.SourceOfTruth, osv.models.utcnow needed
    bug_model: Optional[osv.models.Bug] = osv.models.Bug.get_by_id(processed_vulnerability.id) # Renamed
    if not bug_model: # New bug
      # Special handling for OSS-Fuzz: if bug not found by ID, it might be an error or new bug.
      # Importer should usually create Bug for OSS-Fuzz via RegressResult processing.
      # This path implies an OSV record from a source repo that OSV-DB doesn't know yet.
      if source_repo.name == 'oss-fuzz':
        logging.warning('Bug %s not found in NDB for OSS-Fuzz source. This might be unexpected.',
                        processed_vulnerability.id)
        # Depending on policy, could create one or skip. Original code skips.
        return

      bug_model = osv.models.Bug(
          db_id=processed_vulnerability.id, # Set db_id, key will use this
          id=processed_vulnerability.id,    # Also set NDB key id
          timestamp=osv.models.utcnow(),    # Creation time
          status=osv.models.BugStatus.PROCESSED, # Assume processed if it's being updated from valid source
          source_of_truth=osv.models.SourceOfTruth.SOURCE_REPO # Default for repo sources
      )
      logging.info("Creating new Bug entity for ID %s from source %s",
                   processed_vulnerability.id, source_repo.name)

    # Update Bug model from Vulnerability proto
    bug_model.update_from_vulnerability(processed_vulnerability)
    bug_model.public = True # Assume vulns from synced sources are public
    if source_modified_dt: # If source had a modified date, store it
        bug_model.import_last_modified = source_modified_dt

    # Ensure source_id is correctly formatted: "SOURCE_NAME:RELATIVE_FILE_PATH"
    # This is crucial for linking Bug to its source file.
    # osv.sources.parse_source_id can check, but here we construct it.
    # For OSS-Fuzz, source_id has a special format (OSS-FUZZ-<testcase_id>)
    # and might already be set correctly if bug_model was pre-existing from internal import.
    # If it's a new bug from oss-fuzz repo, this needs care.
    # The original code checks `source_repo.name != 'oss-fuzz' or not bug.source_id`.
    # This implies if it *is* oss-fuzz and source_id is already set (from internal route), don't overwrite.
    # If it's a new bug from oss-fuzz *repo*, then source_id should be set.
    if source_repo.name != 'oss-fuzz' or not bug_model.source_id:
      bug_model.source_id = f'{source_repo.name}:{relative_file_path}'

    # Update status based on withdrawn field
    if bug_model.withdrawn: # If withdrawn timestamp is set
      bug_model.status = osv.models.BugStatus.INVALID
    else: # Not withdrawn, ensure it's PROCESSED
      bug_model.status = osv.models.BugStatus.PROCESSED
      # If it has no affected packages after filtering, mark as INVALID.
      if not processed_vulnerability.affected:
        logging.info('Vulnerability %s has no supported affected packages after filtering. Marking as INVALID.',
                     processed_vulnerability.id)
        bug_model.status = osv.models.BugStatus.INVALID
        # Consider if withdrawn should also be set here. Original only sets status.

    try:
      bug_model.put()
    except (google.api_core.exceptions.Cancelled, ndb.exceptions.Error) as e: # Catch specific NDB/API errors
      # Add note to exception is Python 3.11+ feature.
      # For compatibility or if add_note is not on all caught exceptions:
      logging.exception('Unexpected NDB/API exception while writing Bug %s to Datastore: %s',
                        processed_vulnerability.id, e)
      # Depending on policy, might re-raise or attempt retry.
      return # Stop processing this vuln on DB error.

    # Update AffectedCommits if analysis yielded commit data
    # osv.models.update_affected_commits needed
    # Ensure bug_model.key and .id() are valid before use
    if bug_model.key and analysis_result_obj.commits:
      osv.models.update_affected_commits(bug_model.key.id(), analysis_result_obj.commits, bug_model.public) # type: ignore[union-attr]

    # Notify relevant ecosystem bridges (e.g., PyPI)
    self._notify_ecosystem_bridge(processed_vulnerability)
    # If successfully processed, remove any prior import findings for this bug
    self._maybe_remove_import_findings(bug_model)

    _state.bug_id = None # Clear thread-local bug_id after processing


  def _notify_ecosystem_bridge(self, vulnerability: vulnerability_pb2.Vulnerability) -> None:
    """Notify ecosystem bridges (e.g., PyPI) about the vulnerability."""
    # Deduplicate ecosystems from all affected packages
    ecosystems_in_vuln: Set[str] = set() # Renamed
    for affected_proto in vulnerability.affected: # Renamed
      if affected_proto.HasField('package') and affected_proto.package.ecosystem:
        ecosystems_in_vuln.add(affected_proto.package.ecosystem)

    for ecosystem_name in ecosystems_in_vuln: # Renamed
      push_topic_name: Optional[str] = _ECOSYSTEM_PUSH_TOPICS.get(ecosystem_name) # Renamed
      if push_topic_name:
        # Re-initialize publisher client per call or use the instance one?
        # Original code re-initializes. This is safer for potential client state issues.
        # However, self._publisher already exists. Let's use that.
        # publisher = pubsub_v1.PublisherClient() # This creates new client each time
        # cloud_project = os.environ['GOOGLE_CLOUD_PROJECT'] # Already done in __init__
        # push_topic_path = publisher.topic_path(cloud_project, ecosystem_push_topic) # Renamed

        # Construct full topic path using instance's publisher & pre-resolved _tasks_topic structure
        # This needs adjustment if _ECOSYSTEM_PUSH_TOPICS stores full paths or just topic IDs.
        # Assuming _ECOSYSTEM_PUSH_TOPICS stores topic IDs, and project is same as worker's.
        # For now, let's assume _tasks_topic logic for path construction is similar.
        # This part needs `self._publisher.topic_path(project_id, topic_id)`
        # The current `self._tasks_topic` is already a full path.
        # If _ECOSYSTEM_PUSH_TOPICS are just topic IDs, then:
        # ecosystem_topic_path = self._publisher.topic_path(os.environ['GOOGLE_CLOUD_PROJECT'], push_topic_name)

        # Simpler: Assume _ECOSYSTEM_PUSH_TOPICS stores full topic string or just ID.
        # If it's just ID, this needs project_id.
        # Given it's a module level dict, it's likely just topic ID.
        # The original code snippet for this part was missing, this is an interpretation.
        # Let's assume project_id is same as worker's GOOGLE_CLOUD_PROJECT.
        project_id = os.environ['GOOGLE_CLOUD_PROJECT']
        full_topic_path = self._publisher.topic_path(project_id, push_topic_name)

        # osv.models.vulnerability_to_dict needed
        vuln_dict = osv.models.vulnerability_to_dict(vulnerability)
        self._publisher.publish(full_topic_path, data=json.dumps(vuln_dict).encode('utf-8'))
        logging.info("Notified bridge for ecosystem %s on topic %s for vuln %s",
                     ecosystem_name, full_topic_path, vulnerability.id)


  def _maybe_remove_import_findings(self, bug_model: osv.models.Bug) -> None: # Renamed vulnerability
    """Remove any stale import findings for a successfully processed Bug."""
    # osv.models.ImportFinding needed
    # Ensure bug_model.id() is available
    bug_id_str = bug_model.id()
    if not bug_id_str: return

    finding_model: Optional[osv.models.ImportFinding] = osv.models.ImportFinding.get_by_id(bug_id_str) # Renamed
    if finding_model and finding_model.key: # Ensure key exists before delete
      logging.info('Removing stale import finding for Bug ID: %s', bug_id_str)
      finding_model.key.delete()


  def _do_process_task(self, subscriber: pubsub_v1.SubscriberClient,
                       subscription_path: str, # Renamed subscription
                       ack_id: str,
                       message: pubsub_types.PubsubMessage, # Use specific PubsubMessage type
                       done_event: threading.Event) -> None:
    """Core logic for processing a single Pub/Sub task message."""
    try:
      # Establish NDB context for this thread if not already done by worker_init
      # The main loop already runs NDB operations in context, so this might be redundant
      # if this function is always called from there. However, explicit context is safer.
      with self._ndb_client.context(): # Assuming self._ndb_client is the global one
        # Set thread-local state for logging
        # Message attributes are Mapping[str, str]
        source_id_attr: Optional[str] = message.attributes.get('source_id')
        source_attr: Optional[str] = message.attributes.get('source')
        _state.source_id = get_source_id(message) or source_attr # Use helper, fallback to 'source'
        _state.bug_id = message.attributes.get('allocated_bug_id') # Can be None

        task_type_attr: Optional[str] = message.attributes.get('type') # Renamed
        if not task_type_attr:
            logging.error("Message missing 'type' attribute: %s", message.attributes)
            # Acknowledge to remove from queue if it's fundamentally unprocessable.
            subscriber.acknowledge(subscription=subscription_path, ack_ids=[ack_id])
            return

        logging.info("Processing task: type=%s, source_id=%s, bug_id=%s",
                     task_type_attr, _state.source_id, _state.bug_id)

        if task_type_attr in ('regressed', 'fixed'):
          # Ensure _state.source_id is not None for oss_fuzz tasks
          if _state.source_id:
            oss_fuzz.process_bisect_task(self._oss_fuzz_dir, task_type_attr, _state.source_id, message)
          else:
            logging.error("oss_fuzz task type '%s' missing source_id.", task_type_attr)
        elif task_type_attr == 'impact':
          try:
            if _state.source_id: # impact task uses source_id (original testcase_id)
              oss_fuzz.process_impact_task(_state.source_id, message)
            else: # allocated_id (OSV ID) might be an alternative if source_id is complex
              logging.error("Impact task missing source_id. Attributes: %s", message.attributes)
          except osv.impact.ImpactError: # osv.impact
            logging.exception('Failed to process impact task for source_id %s:', _state.source_id)
        elif task_type_attr == 'invalid':
          mark_bug_invalid(message)
        elif task_type_attr == 'update':
          self._source_update(message)
        else:
            logging.error("Unknown task type: %s", task_type_attr)

        # Clear thread-local state after processing
        _state.source_id = None
        _state.bug_id = None
        subscriber.acknowledge(subscription=subscription_path, ack_ids=[ack_id])
        logging.info("Successfully processed and acknowledged task: type=%s, source_id=%s",
                     task_type_attr, get_source_id(message) or message.attributes.get('source'))

    except Exception: # Catch all exceptions from task processing
      logging.exception('Unexpected exception while processing task (ack_id: %s):', ack_id)
      # Nack the message (or let lease expire) so it can be retried.
      # Modifying ack deadline to 0 causes immediate redelivery.
      try:
        subscriber.modify_ack_deadline(
            subscription=subscription_path, ack_ids=[ack_id], ack_deadline_seconds=0)
      except Exception: # Errors during nack are also possible
          logging.exception("Failed to Nack message (ack_id: %s) after task processing error:", ack_id)
    finally:
      logging.debug('Ending task processing for ack_id: %s', ack_id)
      done_event.set() # Signal leaser thread that this task is finished


  def handle_timeout(self, subscriber: pubsub_v1.SubscriberClient,
                     subscription_path: str, # Renamed
                     ack_id: str,
                     message: pubsub_types.PubsubMessage) -> None: # Use specific type
    """Handle a task timeout: acknowledge and log."""
    # Acknowledge the message to prevent redelivery if timeout means unrecoverable.
    # If timeout implies retry is okay, then don't ack or nack with 0.
    # Current logic acknowledges it.
    subscriber.acknowledge(subscription=subscription_path, ack_ids=[ack_id])

    task_type_attr: Optional[str] = message.attributes.get('type') # Renamed
    source_id_val: Optional[str] = get_source_id(message) or message.attributes.get('source') # Renamed

    logging.warning('Task %s timed out (source_id=%s, ack_id=%s). Message acknowledged.',
                    task_type_attr, source_id_val, ack_id)

    # Specific timeout handling for OSS-Fuzz bisect tasks
    if task_type_attr in ('fixed', 'regressed') and source_id_val:
      oss_fuzz.handle_timeout(task_type_attr, source_id_val, self._oss_fuzz_dir, message)


  def _log_task_latency(self, message: pubsub_types.PubsubMessage) -> None:
    """Determine how long ago the task was requested and log its E2E latency."""
    # Message attributes are Mapping[str, str]
    req_timestamp_str: Optional[str] = message.attributes.get('req_timestamp') # Renamed
    if req_timestamp_str:
      try:
        request_time_epoch: int = int(req_timestamp_str) # Renamed
        # Latency in seconds from original request time to now (finished processing)
        processing_latency_seconds: int = int(time.time()) - request_time_epoch # Renamed

        task_type_attr: Optional[str] = message.attributes.get('type') # Renamed
        source_id_val: Optional[str] = get_source_id(message) or message.attributes.get('source') # Renamed

        logging.info('Task E2E latency: type=%s, source_id=%s, latency=%ds',
                     task_type_attr, source_id_val, processing_latency_seconds)
      except ValueError:
        logging.warning("Invalid req_timestamp format in message attributes: %s", req_timestamp_str)


  def loop(self) -> None:
    """Main task processing loop: pull from Pub/Sub, process, manage lease."""
    subscriber = pubsub_v1.SubscriberClient()
    # GOOGLE_CLOUD_PROJECT should be set in env.
    cloud_project_id: str = os.environ['GOOGLE_CLOUD_PROJECT'] # Renamed
    subscription_path: str = subscriber.subscription_path(cloud_project_id, TASK_SUBSCRIPTION) # Renamed

    # Inner function to process a single message.
    # This structure helps manage setup/teardown per message if needed.
    def _process_single_message(ack_id_str: str, message_obj: pubsub_types.PubsubMessage) -> None: # Renamed
      """Process a single Pub/Sub message, including artifact cleanup and timeout handling."""
      # Ensure OSS-Fuzz repo is up-to-date and clean for tasks that might use it.
      # osv.repos.ensure_updated_checkout needed
      try:
        osv.repos.ensure_updated_checkout(OSS_FUZZ_GIT_URL, self._oss_fuzz_dir,
                                          git_callbacks=None) # No specific callbacks for public repo
      except osv.repos.GitCloneError as e:
          logging.error("Failed to update OSS-Fuzz repo at %s: %s. Some tasks might fail.", self._oss_fuzz_dir, e)
          # Decide if this is fatal for all tasks or if some can proceed.
          # For now, continue processing tasks but log the error.

      clean_artifacts(self._oss_fuzz_dir) # Clean before task

      # Enforce timeout by doing the work in another thread.
      task_done_event = threading.Event() # Renamed
      processing_thread = threading.Thread( # Renamed
          target=self._do_process_task,
          args=(subscriber, subscription_path, ack_id_str, message_obj, task_done_event),
          daemon=True) # Daemon thread allows main program to exit even if thread is running (though join is used)

      logging.info('Starting processing thread for Pub/Sub message ack_id: %s, attributes: %s',
                   ack_id_str, message_obj.attributes)
      processing_thread.start()

      # Wait for the task to complete or timeout.
      # MAX_LEASE_DURATION is the absolute max time we'll keep renewing lease and waiting.
      task_completed_within_timeout: bool = task_done_event.wait(timeout=MAX_LEASE_DURATION) # Renamed

      logging.info('Processing thread for ack_id %s finished or timed out.', ack_id_str)
      if task_completed_within_timeout:
        self._log_task_latency(message_obj) # Log latency if completed
      else: # Task timed out
        self.handle_timeout(subscriber, subscription_path, ack_id_str, message_obj)
        logging.warning('Task processing timed out for ack_id: %s', ack_id_str)
        # If thread is still alive due to timeout, it might continue running but its results are ignored.
        # Consider if thread needs explicit termination attempt if that's critical and safe.
        # (Python threads cannot be forcibly killed easily/safely).

    # Main loop to pull messages
    while True:
      try:
        # Pull one message at a time. Flow control handled by lease management.
        pull_response = subscriber.pull(subscription=subscription_path, max_messages=1) # Renamed
        if not pull_response.received_messages:
          # No messages, wait a bit before polling again (optional, pull might block)
          # time.sleep(10) # Example: sleep if pull is non-blocking and frequently empty
          continue # Go back to start of while True to pull again
      except Exception: # Catch errors during pull itself
          logging.exception("Error pulling message from Pub/Sub subscription %s. Retrying.", subscription_path)
          time.sleep(60) # Wait before retrying pull on error
          continue


      # Process the first (and only, due to max_messages=1) message received.
      received_msg_info = pull_response.received_messages[0] # Renamed message
      current_ack_id: str = received_msg_info.ack_id # Renamed ack_id
      current_message: pubsub_types.PubsubMessage = received_msg_info.message # Renamed message

      # Start a leaser thread for this message.
      leaser_done_event = threading.Event() # Renamed
      leaser_thread = _PubSubLeaserThread( # Renamed leaser
          subscriber, subscription_path, current_ack_id,
          leaser_done_event, MAX_LEASE_DURATION)
      leaser_thread.start()

      try:
        # Process the task itself.
        _process_single_message(current_ack_id, current_message)
      except Exception:
          # This catches errors in _process_single_message's main logic before thread start,
          # or if _process_single_message itself raises directly (which it shouldn't if thread handles all).
          logging.exception("Critical error in task processing dispatcher for ack_id %s.", current_ack_id)
          # Ensure lease is not held indefinitely if dispatcher fails before _do_process_task.
          # This might mean nacking or letting lease expire.
          # For now, ensure leaser thread is signaled to stop.
      finally:
        # Signal the leaser thread that task processing is complete (or has failed terminally).
        leaser_done_event.set()
        leaser_thread.join(timeout=self. _PubSubLeaserThread.EXTENSION_TIME_SECONDS + 5) # Wait for leaser to finish
        if leaser_thread.is_alive():
            logging.warning("Leaser thread for ack_id %s did not terminate cleanly.", current_ack_id)


def main() -> None: # main usually doesn't return a value, or 0 for success / non-0 for error
   # Argument parsing
  parser = argparse.ArgumentParser(description='OSV Worker')
  parser.add_argument(
      '--work_dir', type=str, help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument('--ssh_key_public', type=str, help='Public SSH key path', default=None)
  parser.add_argument('--ssh_key_private', type=str, help='Private SSH key path', default=None)
  parser.add_argument(
      '--redis_host', type=str, help='Hostname/IP of Redis instance for caching', default=None)
  parser.add_argument(
      '--redis_port', type=int, default=6379, help='Port of Redis instance')
  args = parser.parse_args()

  # Configure Redis cache if host is provided
  if args.redis_host:
    # osv.ecosystems.config is not standard, assuming a global config object or direct use.
    # For now, let's assume RedisCache can be instantiated and set as a global cache if needed.
    # This part might need refactoring if `osv.ecosystems.config.set_cache` is specific.
    # If it's a global cache for ecosystems:
    # ecosystems.set_cache(RedisCache(args.redis_host, args.redis_port))
    # If it's a general purpose cache used by osv.cache.cached decorator, that needs setup.
    # For now, just instantiating it. If it's meant for osv.cache.shared_cache:
    # osv.cache.shared_cache = RedisCache(args.redis_host, args.redis_port)
    # This depends on how osv.cache is structured.
    # Let's assume it's for a generic cache mechanism used by some OSV parts.
    logging.info("Using Redis cache at %s:%d", args.redis_host, args.redis_port)
    # This RedisCache setup might need to be passed to where it's used, e.g. TaskRunner,
    # or set on a global/module level accessible by `osv.cache.cached`.
    # For now, just creating an instance to ensure type checking works for RedisCache itself.
    _ = RedisCache(args.redis_host, args.redis_port) # Instance not used here, assumes global setup elsewhere.

  # Set working directory for ecosystems module if it uses one globally
  # osv.ecosystems.config.work_dir = args.work_dir # Assuming this global config exists

  # Work around kernel bug: https://gvisor.dev/issue/1765 (RLIMIT_MEMLOCK)
  try:
    resource.setrlimit(resource.RLIMIT_MEMLOCK,
                       (resource.RLIM_INFINITY, resource.RLIM_INFINITY))
  except Exception as e:
    logging.warning("Failed to set RLIMIT_MEMLOCK: %s. This might be okay if not in gVisor.", e)


  # Start Docker service if not running (relevant in some environments)
  try:
    subprocess.check_call(('service', 'docker', 'start')) # Use check_call to raise on error
  except subprocess.CalledProcessError as e:
    logging.warning("Failed to start docker service: %s. This might be okay if docker is already running or not needed.", e)
  except FileNotFoundError:
    logging.warning("'service' command not found. Assuming docker is managed externally or not needed.")


  oss_fuzz_checkout_dir = os.path.join(args.work_dir, 'oss-fuzz') # Renamed

  # Ensure temporary directory exists and is clean
  # This is a persistent temp dir, not auto-cleaned by tempfile.TemporaryDirectory
  persistent_tmp_dir = os.path.join(args.work_dir, 'tmp_worker_persistent') # Renamed
  if os.path.exists(persistent_tmp_dir):
    shutil.rmtree(persistent_tmp_dir)
  os.makedirs(persistent_tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = persistent_tmp_dir # For processes that use TMPDIR

  # Add oss-fuzz/infra to Python path for direct imports by OSS-Fuzz scripts
  # This is a common pattern for OSS-Fuzz's infra tooling.
  oss_fuzz_infra_path = os.path.join(oss_fuzz_checkout_dir, 'infra')
  if oss_fuzz_infra_path not in sys.path:
    sys.path.append(oss_fuzz_infra_path)

  # Suppress verbose logs from OSS-Fuzz's 'helper' module during bisection
  logging.getLogger('helper').setLevel(logging.CRITICAL)

  # Ensure OSS-Fuzz repository is checked out and up-to-date
  # osv.repos.ensure_updated_checkout needed
  try:
    osv.repos.ensure_updated_checkout(OSS_FUZZ_GIT_URL, oss_fuzz_checkout_dir)
  except osv.repos.GitCloneError as e:
      logging.error("Failed to checkout or update OSS-Fuzz repo at %s: %s. Worker may not function correctly.",
                    oss_fuzz_checkout_dir, e)
      # Depending on how critical OSS-Fuzz repo is, might exit or continue with limited functionality.
      # For now, assume it's critical.
      sys.exit(1)


  # Initialize NDB client and TaskRunner within NDB context for main operations
  # _ndb_client is global, assigned here.
  global _ndb_client
  _ndb_client = ndb.Client()
  with _ndb_client.context():
    task_runner = TaskRunner(
        _ndb_client, # Pass the initialized client
        oss_fuzz_checkout_dir,
        args.work_dir,
        args.ssh_key_public,
        args.ssh_key_private
    )
    task_runner.loop() # Start the main processing loop


if __name__ == '__main__':
  osv.logs.setup_gcp_logging('osv-worker') # Renamed service from 'worker' for clarity
  _setup_logging_extra_info() # Attach custom fields to logs
  main()
