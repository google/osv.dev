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
from __future__ import annotations

import argparse
import concurrent.futures
import datetime
import json
import logging
import os
import shutil
import threading
import time
import atexit # Keep atexit for log_run_duration
from typing import (Any, Callable, Dict, List, NamedTuple, Optional, Set,
                    Tuple, Type) # Added Set, Type, Dict, Any, Callable

from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud import storage
from google.cloud.storage import retry as gcs_retry # Alias to avoid conflict
from google.cloud.storage.bucket import Bucket # For type hint
from google.cloud.storage.blob import Blob # For type hint
from google.cloud.exceptions import NotFound
import pygit2 # For pygit2 objects
import pygit2.enums

import requests
from requests.adapters import HTTPAdapter
from urllib3.util import Retry # For requests.adapters.HTTPAdapter retry strategy

import osv.models # For NDB models like Bug, SourceRepository, etc.
import osv.repos # For GitRemoteCallback
import osv.logs # For setup_gcp_logging
from osv import sources # For source_path, parse_source_id, etc.
from osv import vulnerability_pb2 # For Vulnerability proto

DEFAULT_WORK_DIR = '/work'
DEFAULT_PUBLIC_LOGGING_BUCKET = 'osv-public-import-logs'

_BUG_REDO_DAYS = 14
_TASKS_TOPIC = 'tasks' # Pub/Sub topic name
_OSS_FUZZ_EXPORT_BUCKET = 'oss-fuzz-osv-vulns'
_EXPORT_WORKERS = 32
_NO_UPDATE_MARKER = 'OSV-NO-UPDATE'
_BUCKET_THREAD_COUNT = 20
_HTTP_LAST_MODIFIED_FORMAT = '%a, %d %b %Y %H:%M:%S %Z' # For parsing Last-Modified header
_TIMEOUT_SECONDS = 60 # For HTTP requests

# Thread-local storage for NDB client, if needed per thread, though typically client is global or passed.
# Original code has this, keeping it. Unused in current snippet.
_client_store = threading.local()

# Global NDB client, initialized in __main__
_ndb_client: ndb.Client


def modify_storage_client_adapters(storage_client: storage.Client,
                                   pool_connections: int = 128,
                                   max_retries_val: int = 3, # Renamed max_retries
                                   pool_block: bool = True) -> storage.Client:
  """Returns a modified google.cloud.storage.Client object.

  Due to many concurrent GCS connections, the default connection pool can become
  overwhelmed, introducing delays.

  Solution described in https://github.com/googleapis/python-storage/issues/253

  These affect the urllib3.HTTPConnectionPool underpinning the storage.Client's
  HTTP requests.

  Args:
    storage_client: an existing google.cloud.storage.Client object
    pool_connections: number of pool_connections desired
    max_retries_val: maximum retries for the adapter.
    pool_block: blocking behaviour when pool is exhausted

  Returns:
    the google.cloud.storage.Client appropriately modified.
  """
  # The requests.adapters.HTTPAdapter max_retries can be an int or a Retry object.
  adapter = HTTPAdapter(
      pool_connections=pool_connections,
      max_retries=max_retries_val, # Assuming int usage based on original code
      pool_block=pool_block)

  # pylint: disable=protected-access
  # Accessing protected members _http and _auth_request is necessary here.
  # This might be fragile if underlying library structure changes.
  http_session = getattr(storage_client, '_http', None)
  if http_session:
      http_session.mount('https://', adapter)
      auth_request_session = getattr(http_session, '_auth_request', None)
      if auth_request_session and hasattr(auth_request_session, 'session'):
          auth_request_session.session.mount('https://', adapter)
      elif auth_request_session: # If _auth_request is the session itself
          auth_request_session.mount('https://', adapter)
  else:
    logging.warning("Could not modify storage client adapters: _http attribute not found.")

  return storage_client


def _is_vulnerability_file(source_repo: osv.models.SourceRepository, file_path: str) -> bool:
  """Return whether or not the file is a Vulnerability entry."""
  # Check if file is within specified directory_path
  if (source_repo.directory_path and
      not file_path.startswith(source_repo.directory_path.rstrip('/') + '/')):
    return False

  # Check against ignore patterns
  if source_repo.ignore_file(file_path): # ignore_file is a method on SourceRepository
    return False

  # Check file extension
  # Ensure source_repo.extension is not None before calling endswith
  return file_path.endswith(source_repo.extension or '.yaml') # Default to .yaml if None


def aestnow() -> datetime.datetime:
  """Get the current AEST time (UTC+10) but represented as a UTC datetime object."""
  # This function's behavior is a bit unusual (AEST time in UTC tz). Preserving it.
  # It effectively shifts UTC time by +10 hours.
  # To clarify: datetime.now(datetime.UTC) gives current UTC time.
  # .astimezone(datetime.timezone(datetime.timedelta(hours=10))) converts it to AEST.
  # .replace(tzinfo=datetime.UTC) then stamps this AEST time as if it were UTC.
  # This is likely for specific comparison or storage needs.
  return datetime.datetime.now(datetime.UTC).astimezone(
      datetime.timezone(datetime.timedelta(hours=10))
  ).replace(tzinfo=datetime.UTC)


def utcnow() -> datetime.datetime:
  """utcnow() for mocking or consistent UTC timestamps."""
  return datetime.datetime.now(datetime.UTC)


def replace_importer_log(gcs_client: storage.Client, # Renamed client
                         source_name: str,
                         bucket_name: str,
                         import_failure_logs: List[str]) -> None:
  """Replace the public importer logs with the new one."""
  bucket: Bucket = gcs_client.bucket(bucket_name)
  # Construct log content
  upload_string = f'--- {datetime.datetime.now(datetime.UTC).isoformat()} ---\n'
  upload_string += '\n'.join(import_failure_logs)

  # Upload to GCS
  blob: Blob = bucket.blob(source_name) # Blob name is the source_name
  blob.upload_from_string(upload_string, retry=gcs_retry.DEFAULT_RETRY) # Use aliased gcs_retry
  logging.info("Replaced importer log for source '%s' in bucket '%s'", source_name, bucket_name)


def log_run_duration(start_time: float) -> None: # Renamed start
  """Log the elapsed wallclock duration at the end of the program.

  This enables a log-based metric to be created.

  Args:
    start_time: the time the program started (from time.time()).
  """
  elapsed_seconds: float = time.time() - start_time # Renamed elapsed
  logging.info('Importer run duration: %.2f seconds', elapsed_seconds) # Use float formatting


class Importer:
  """Importer."""

  _ssh_key_public_path: Optional[str]
  _ssh_key_private_path: Optional[str]
  _work_dir: str
  _publisher: pubsub_v1.PublisherClient
  _tasks_topic: str
  _public_log_bucket: str
  _oss_fuzz_export_bucket: str
  _sources_dir: str
  _strict_validation: bool
  _delete: bool
  _deletion_safety_threshold_pct: float

  def __init__(self,
               ssh_key_public_path: Optional[str], # Can be None
               ssh_key_private_path: Optional[str], # Can be None
               work_dir: str,
               public_log_bucket: str,
               oss_fuzz_export_bucket: str, # Should match _OSS_FUZZ_EXPORT_BUCKET constant
               strict_validation: bool,
               delete: bool,
               deletion_safety_threshold_pct: float = 10.0) -> None:
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path
    self._work_dir = work_dir
    self._publisher = pubsub_v1.PublisherClient()

    # GOOGLE_CLOUD_PROJECT should be set in the environment
    project_id: Optional[str] = os.getenv('GOOGLE_CLOUD_PROJECT')
    if not project_id:
        # Fallback or error if project ID not found.
        # This was using os.environ directly before, which would raise KeyError if not set.
        # Using getenv with a fallback or check is safer.
        # For now, assume it's set as per original direct access.
        project_id = os.environ['GOOGLE_CLOUD_PROJECT']

    self._tasks_topic = self._publisher.topic_path(project_id, _TASKS_TOPIC)
    self._public_log_bucket = public_log_bucket
    self._oss_fuzz_export_bucket = oss_fuzz_export_bucket

    self._sources_dir = os.path.join(self._work_dir, 'sources')
    self._strict_validation = strict_validation
    self._delete = delete
    self._deletion_safety_threshold_pct = deletion_safety_threshold_pct
    os.makedirs(self._sources_dir, exist_ok=True)

  def _git_callbacks(self, source_repo: osv.models.SourceRepository) -> Optional[osv.repos.GitRemoteCallback]:
    """Get git auth callbacks. Returns None if SSH keys are not configured."""
    if not source_repo.repo_username or \
       not self._ssh_key_public_path or \
       not self._ssh_key_private_path:
      # This can happen if the SourceRepository doesn't use SSH auth, or keys are not provided.
      # osv.repos.GitRemoteCallback requires these.
      return None

    return osv.repos.GitRemoteCallback(source_repo.repo_username,
                                       self._ssh_key_public_path,
                                       self._ssh_key_private_path)

  def _request_analysis(self, bug: osv.models.Bug,
                        source_repo: osv.models.SourceRepository,
                        repo: pygit2.Repository) -> None:
    """Request analysis based on bug's source_of_truth."""
    # osv.models.SourceOfTruth needed
    if bug.source_of_truth == osv.models.SourceOfTruth.SOURCE_REPO:
      # osv.sources.source_path, osv.sources.repo_path, osv.sources.sha256 needed
      path = sources.source_path(source_repo, bug)
      file_path = os.path.join(sources.repo_path(repo), path)
      if not os.path.exists(file_path):
        logging.info(
            'Skipping analysis for Bug ID %s as its source file %s no longer exists.',
            bug.id(), path) # Use bug.id() for logging
        return

      original_sha256 = sources.sha256(file_path) # Use sources.sha256
      self._request_analysis_external(source_repo, original_sha256, path)
    else: # INTERNAL or other sources
      self._request_internal_analysis(bug)

  def _request_analysis_external(self,
                                 source_repo: osv.models.SourceRepository,
                                 original_sha256: str,
                                 path: str,
                                 deleted: bool = False) -> None:
    """Request analysis for externally sourced vulnerabilities (SOURCE_REPO)."""
    self._publisher.publish(
        self._tasks_topic,
        data=b'', # No specific data payload for this type of task
        type='update', # Task type: update from source
        source=source_repo.name,
        path=path, # Path within the source repo
        original_sha256=original_sha256,
        deleted=str(deleted).lower(), # Convert bool to string "true"/"false"
        req_timestamp=str(int(time.time())) # Current timestamp as string
    )

  def _request_internal_analysis(self, bug: osv.models.Bug) -> None:
    """Request internal analysis (e.g., for impact assessment of internal bugs)."""
    # Ensure bug.key and bug.key.id() exist
    bug_key_id = bug.key.id() if bug.key else "UNKNOWN_KEY_ID"

    self._publisher.publish(
        self._tasks_topic,
        data=b'',
        type='impact', # Task type: assess impact
        source_id=bug.source_id or "UNKNOWN_SOURCE_ID", # Ensure source_id is not None
        allocated_id=bug_key_id, # The OSV Bug ID
        req_timestamp=str(int(time.time()))
    )

  def _infer_id_from_invalid_data(self, name: str, content: bytes) -> str:
    """Best effort infer the bug ID for data that failed to parse.

    First try and extract something that looks like an "id" field from the
    content (if it's JSON-like), and failing that, infer from the filename.

    Args:
      name: The name/path associated with the data (e.g., filename).
      content: The raw byte content of the data.

    Returns:
      A string representing the inferred identifier.
    """
    # Attempt to parse as JSON and get 'id' field
    try:
        data_dict = json.loads(content.decode('utf-8'))
        if isinstance(data_dict, dict) and 'id' in data_dict and isinstance(data_dict['id'], str):
            return data_dict['id']
        # If it's a list of vulns (less common for single file error)
        if isinstance(data_dict, list) and data_dict and \
           isinstance(data_dict[0], dict) and 'id' in data_dict[0] and \
           isinstance(data_dict[0]['id'], str):
            return data_dict[0]['id']
    except (json.JSONDecodeError, UnicodeDecodeError, TypeError):
        # Content is not valid JSON or not utf-8, proceed to filename inference.
        pass

    # Fallback: try parsing with osv's parser (non-strict)
    # osv.sources.parse_vulnerabilities_from_data needed
    file_extension = os.path.splitext(name)[1]
    try:
      # This expects string data, so decode content.
      vulns: List[vulnerability_pb2.Vulnerability] = sources.parse_vulnerabilities_from_data(
          content.decode('utf-8'), file_extension, strict=False)
      if vulns and vulns[0].id: # Check if list is non-empty and first vuln has an id
        return vulns[0].id
    except RuntimeError:  # Unknown format by parse_vulnerabilities_from_data
      pass
    except Exception: # Catch any other parsing errors
      # This function is often called from an exception handler, avoid raising new ones.
      logging.debug("Secondary parsing attempt failed in _infer_id_from_invalid_data for %s", name, exc_info=True)
      pass

    # Final fallback: infer from filename
    return os.path.splitext(os.path.basename(name))[0]

  def _record_quality_finding(
      self,
      source_repo_name: str, # Renamed source
      bug_id: str,
      new_finding: osv.models.ImportFindings = osv.models.ImportFindings.INVALID_JSON # Renamed, use models
  ) -> None:
    """Record the quality finding about a record in Datastore.

    Args:
      source_repo_name: The name of the source repository.
      bug_id: The ID of the vulnerability.
      new_finding: The finding to record.

    Sets the finding's last_attempt to now, and adds the finding to the list of
    findings for the record (if any already exist).
    """
    # osv.models.ImportFinding, osv.models.ImportFindings needed
    current_time = utcnow() # Consistent timestamp for the operation

    existing_finding_model: Optional[osv.models.ImportFinding] = osv.models.ImportFinding.get_by_id(bug_id) # Renamed

    if existing_finding_model:
      # Ensure `findings` list exists, append if new finding not already present.
      if existing_finding_model.findings is None: # Should not happen if model defines default=[]
          existing_finding_model.findings = []
      if new_finding not in existing_finding_model.findings:
        existing_finding_model.findings.append(new_finding)

      existing_finding_model.last_attempt = current_time
      existing_finding_model.put()
    else: # No existing finding, create a new one
      new_finding_model = osv.models.ImportFinding(
          id=bug_id, # Explicitly set NDB key ID
          bug_id=bug_id, # Also store as property if needed for queries
          source=source_repo_name,
          findings=[new_finding],
          first_seen=current_time,
          last_attempt=current_time)
      new_finding_model.put()

  def run(self) -> None:
    """Run importer for all configured source repositories."""
    # osv.models.SourceRepository needed
    source_repo_query: ndb.Query[osv.models.SourceRepository] = osv.models.SourceRepository.query()

    current_source_repo: osv.models.SourceRepository # Type hint for loop var, renamed
    for current_source_repo in source_repo_query:
      try:
        logging.info("Processing source repository: %s", current_source_repo.name)
        if not self._delete and current_source_repo.name == 'oss-fuzz':
          # Special handling for oss-fuzz source if not in delete mode
          self.process_oss_fuzz(current_source_repo)

        self.validate_source_repo(current_source_repo) # Validate settings

        if not self._delete: # Process updates if not in delete mode
          self.process_updates(current_source_repo)
        else: # Process deletions if in delete mode
          self.process_deletions(current_source_repo)

      except Exception: # Catch broad exceptions per source_repo to allow others to proceed
        logging.exception("Error processing source repository: %s", current_source_repo.name)


  def checkout(self, source_repo: osv.models.SourceRepository) -> pygit2.Repository:
    """Check out a source repo, ensuring it's updated."""
    # osv.repos.ensure_updated_checkout needed
    # Path where this source repo will be checked out locally
    local_repo_path = os.path.join(self._sources_dir, source_repo.name)

    return osv.repos.ensure_updated_checkout(
        source_repo.repo_url, # Assuming repo_url is always set for GIT type
        local_repo_path,
        git_callbacks=self._git_callbacks(source_repo), # Can be None
        branch=source_repo.repo_branch # Can be None
    )

  def import_new_oss_fuzz_entries(self, repo: pygit2.Repository,
                                  oss_fuzz_source_repo: osv.models.SourceRepository) -> None: # Renamed oss_fuzz_source
    """Import new entries from OSS-Fuzz into its source repository."""
    exported_bugs_to_update_ndb: List[osv.models.Bug] = [] # Renamed exported

    # Query for internal OSS-Fuzz bugs that are processed and public
    # osv.models.Bug, osv.models.SourceOfTruth, osv.models.BugStatus needed
    internal_oss_fuzz_bugs_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query(
        osv.models.Bug.source_of_truth == osv.models.SourceOfTruth.INTERNAL,
        osv.models.Bug.status == osv.models.BugStatus.PROCESSED,
        osv.models.Bug.public == True # noqa: E712
    )

    current_bug: osv.models.Bug # Type hint for loop var, renamed bug
    for current_bug in internal_oss_fuzz_bugs_query:
      # Ensure source_id is present to parse source name
      if not current_bug.source_id: continue

      # osv.sources.parse_source_id needed
      source_name, _ = sources.parse_source_id(current_bug.source_id)
      # Only process if bug's source name matches the oss_fuzz_source_repo's name
      if source_name != oss_fuzz_source_repo.name:
        continue

      # Determine path where vulnerability YAML/JSON should be written
      # osv.sources.repo_path, osv.sources.source_path needed
      # Ensure source_repo.extension is not None (it has a default in model)
      vuln_file_path = os.path.join( # Renamed vulnerability_path
          sources.repo_path(repo),
          sources.source_path(oss_fuzz_source_repo, current_bug)
      )
      os.makedirs(os.path.dirname(vuln_file_path), exist_ok=True)

      if os.path.exists(vuln_file_path): # Skip if file already exists
        continue

      logging.info('Writing OSS-Fuzz sourced bug %s to file %s', current_bug.id(), vuln_file_path)
      # osv.models.write_vulnerability needed
      osv.models.write_vulnerability(current_bug.to_vulnerability(), vuln_file_path)

      # Mark the bug's source_of_truth as SOURCE_REPO now that it's in the git repo
      current_bug.source_of_truth = osv.models.SourceOfTruth.SOURCE_REPO
      exported_bugs_to_update_ndb.append(current_bug)

    # If any files were written, commit and push changes to the Git repository
    if not exported_bugs_to_update_ndb: # Check list directly, not diff (which was removed)
      logging.info('No new OSS-Fuzz entries to commit to %s.', oss_fuzz_source_repo.name)
      return

    # Add all changes, commit, and push
    repo.index.add_all()
    # Check if there are actual changes staged for commit
    # repo.head.peel().tree can be None if repo is empty or head is unborn
    head_tree = repo.head.peel(pygit2.Tree) if repo.head else None
    if head_tree is None and not list(repo.index): # No head and empty index means nothing to diff/commit
        logging.info('No changes to commit to %s (empty repo or index).', oss_fuzz_source_repo.name)
        return

    # Diff against HEAD's tree if available, otherwise against empty tree for initial commit
    diff_to_commit: Optional[pygit2.Diff] = repo.index.diff_to_tree(head_tree) if head_tree else None

    if not diff_to_commit and head_tree : # No changes if diff is empty and there was a HEAD
        logging.info('No new entries or changes to commit to %s.', oss_fuzz_source_repo.name)
        return

    logging.info('Committing and pushing %d new/updated OSS-Fuzz entries to %s.',
                 len(exported_bugs_to_update_ndb), oss_fuzz_source_repo.name)
    # osv.repos.push_source_changes needed
    if osv.repos.push_source_changes(repo, 'Import from OSS-Fuzz',
                                     self._git_callbacks(oss_fuzz_source_repo)):
      ndb.put_multi(exported_bugs_to_update_ndb) # Update Bug entities in NDB
    else:
      logging.error("Failed to push OSS-Fuzz changes to %s.", oss_fuzz_source_repo.name)


  def schedule_regular_updates(self, repo: pygit2.Repository,
                               source_repo: osv.models.SourceRepository) -> None:
    """Schedule regular updates for bugs from a source repository."""
    current_aest_time: datetime.datetime = aestnow() # Renamed

    # Check if updates were already scheduled today (AEST)
    if (source_repo.last_update_date and source_repo.last_update_date.date() >= current_aest_time.date()):
      logging.info("Updates already scheduled today for source: %s", source_repo.name)
      return

    # Query for unfixed, processed, public bugs from this source
    # osv.models.Bug, osv.models.BugStatus needed
    unfixed_bugs_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query( # Renamed
        osv.models.Bug.status == osv.models.BugStatus.PROCESSED,
        osv.models.Bug.is_fixed == False,  # noqa: E712
        osv.models.Bug.source == source_repo.name,
        osv.models.Bug.public == True # Only schedule for public bugs
    )

    current_bug: osv.models.Bug # Type hint for loop var
    for current_bug in unfixed_bugs_query:
      self._request_analysis(current_bug, source_repo, repo)

    # Re-analyze bugs (even fixed ones) that were last modified recently (_BUG_REDO_DAYS)
    # This is to catch cases where fixes might be reverted or new info comes up.
    redo_cutoff_time: datetime.datetime = current_aest_time - datetime.timedelta(days=_BUG_REDO_DAYS) # Renamed

    # Query for processed, public bugs from this source, modified after cutoff
    # osv.models.Bug, osv.models.BugStatus needed
    recent_bugs_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query( # Renamed query
        osv.models.Bug.status == osv.models.BugStatus.PROCESSED,
        osv.models.Bug.source == source_repo.name,
        osv.models.Bug.timestamp >= redo_cutoff_time, # Check against bug's main timestamp
        osv.models.Bug.public == True
    )

    for current_bug in recent_bugs_query: # Renamed bug
      # Ensure key exists for logging
      bug_key_id = current_bug.key.id() if current_bug.key else "UNKNOWN_KEY"
      logging.info('Re-requesting impact analysis for recently modified/created bug: %s', bug_key_id)

      # The original logic skipped re-analysis for unfixed bugs here because
      # the previous loop already handled them. This is correct.
      if not current_bug.is_fixed:
        continue
      self._request_analysis(current_bug, source_repo, repo)

    # Update the source_repo's last_update_date
    source_repo.last_update_date = current_aest_time
    source_repo.put()
    logging.info("Finished scheduling regular updates for source: %s", source_repo.name)


  def _vuln_ids_from_gcs_blob(self, gcs_client: storage.Client, # Renamed client
                              source_repo: osv.models.SourceRepository,
                              blob: Blob) -> Optional[List[str]]: # Return List not Tuple
    """Returns a list of vulnerability IDs from a parsable OSV GCS blob.

    Returns None if the blob is not a vulnerability file or cannot be retrieved.
    """
    if not _is_vulnerability_file(source_repo, blob.name): # blob.name can be None
      return None

    try:
      # Download, being careful about blob potentially changing (generation=None).
      # Ensure blob.bucket is valid if blob comes from listing.
      if not blob.bucket: return None # Should not happen for listed blobs

      # Use the passed client, not a new one.
      blob_to_download = Blob(blob.name, blob.bucket, generation=None) # Create new Blob instance for download
      blob_bytes: bytes = blob_to_download.download_as_bytes(client=gcs_client) # Pass client
    except NotFound:
      logging.warning("Blob %s not found during download attempt.", blob.name)
      return None
    except Exception as e: # Catch other potential download errors
      logging.error("Error downloading blob %s: %s", blob.name, e)
      return None

    found_vuln_ids: List[str] = [] # Renamed vuln_ids
    try:
      # osv.sources.parse_vulnerabilities_from_data needed
      # Ensure blob.name is not None before os.path.splitext
      file_extension = os.path.splitext(blob.name or "")[1]
      # This may raise jsonschema.exceptions.ValidationError if strict validation fails
      vulns_from_blob: List[vulnerability_pb2.Vulnerability] = sources.parse_vulnerabilities_from_data( # Renamed vulns
          blob_bytes.decode('utf-8'), # Expects string data
          file_extension,
          strict=source_repo.strict_validation and self._strict_validation)

      for vuln_proto in vulns_from_blob: # Renamed vuln
        if vuln_proto.id: # Ensure ID is present
          found_vuln_ids.append(vuln_proto.id)
    except Exception as e: # Catch parsing or validation errors
        # Log error, but don't let one bad file stop all processing for a source.
        logging.error("Error parsing or validating blob %s: %s", blob.name, e)
        # Optionally record this finding using _record_quality_finding
        inferred_id = self._infer_id_from_invalid_data(blob.name or "unknown_blob", blob_bytes)
        self._record_quality_finding(source_repo.name, inferred_id, osv.models.ImportFindings.INVALID_JSON)
        return None # Indicate failure for this blob

    return found_vuln_ids


  def _convert_blob_to_vuln(
      self, storage_client: storage.Client,
      ndb_client_instance: ndb.Client, # Renamed ndb_client
      source_repo: osv.models.SourceRepository,
      blob: Blob, # Use storage.Blob directly
      ignore_last_import_time: bool
  ) -> Optional[Tuple[str, str]]: # Returns (sha256_hash, blob_name) or None
    """Parse a GCS blob, check if it needs update, return (hash, blob_name) if so.

    Returns None if:
    - Blob is not a vulnerability file.
    - Blob hasn't been updated since last import (and not ignoring import time).
    - Blob content (vulnerability) hasn't changed compared to NDB record.
    - Parsing/validation fails (error logged, finding recorded).
    """
    # Ensure blob.name and blob.updated are not None before use
    if not blob.name or not _is_vulnerability_file(source_repo, blob.name):
      return None

    # Ensure source_repo.last_update_date is datetime, default to min if None
    last_repo_update_dt = source_repo.last_update_date or datetime.datetime.min.replace(tzinfo=datetime.UTC)

    # If not ignoring import time, and blob hasn't been updated since last repo update, skip.
    if not ignore_last_import_time and blob.updated and blob.updated <= last_repo_update_dt:
      return None

    logging.info('Processing GCS blob: %s/%s (updated: %s, last_repo_update: %s)',
                 source_repo.bucket, blob.name, blob.updated, last_repo_update_dt)

    try:
      # Download (generation-agnostic)
      blob_to_download = Blob(blob.name, blob.bucket, generation=None) # Use full Blob type
      blob_bytes: bytes = blob_to_download.download_as_bytes(client=storage_client)
    except NotFound:
      logging.warning("Blob %s not found during download (convert_blob_to_vuln).", blob.name)
      return None
    except Exception as e:
      logging.error("Error downloading blob %s (convert_blob_to_vuln): %s", blob.name, e)
      return None

    blob_sha256_hash: str = sources.sha256_bytes(blob_bytes) # Use sources.sha256_bytes, renamed

    try:
      # Parse all vulnerabilities from the blob (usually one, but can be list)
      # osv.sources.parse_vulnerabilities_from_data needed
      vulns_from_blob: List[vulnerability_pb2.Vulnerability] = sources.parse_vulnerabilities_from_data( # Renamed
          blob_bytes.decode('utf-8'), # Expects string
          os.path.splitext(blob.name)[1], # File extension
          strict=self._strict_validation # Use instance strict_validation setting
      )
    except Exception as e: # Broad catch for parsing/validation errors
        logging.error("Failed to parse/validate blob %s: %s", blob.name, e)
        inferred_id = self._infer_id_from_invalid_data(blob.name, blob_bytes)
        self._record_quality_finding(source_repo.name, inferred_id, osv.models.ImportFindings.INVALID_JSON)
        return None # Skip this blob

    if not vulns_from_blob: # No valid vulnerabilities parsed
        logging.warning("No valid vulnerabilities found in blob %s", blob.name)
        return None

    # If re-importing all, no need to check NDB for changes.
    if ignore_last_import_time:
      return blob_sha256_hash, blob.name

    # Typical path: check if any vulnerability in the blob is new or changed.
    # Need NDB context for this part.
    ndb_context_obj = ndb.context.get_context(False) # Renamed ndb_ctx
    if ndb_context_obj is None: # Should be set by the ThreadPoolExecutor's worker_init
      logging.error("NDB context not found in _convert_blob_to_vuln thread.")
      # Cannot proceed without NDB context. This indicates a setup issue.
      # Depending on desired robustness, could try to establish one, or fail.
      # For now, assume context is expected to be present.
      return None # Or raise an error

    with ndb_context_obj.use(): # type: ignore[union-attr] # ndb_context_obj is not None here
      for vuln_proto in vulns_from_blob: # Renamed vuln
        if not vuln_proto.id: continue # Skip if somehow a vuln has no ID after parsing

        # osv.models.Bug needed
        bug_model: Optional[osv.models.Bug] = osv.models.Bug.get_by_id(vuln_proto.id) # Renamed bug

        # Check if bug is new or if its stored import_last_modified differs from proto's modified.
        # vuln_proto.modified is a Timestamp. Convert to datetime for comparison.
        # Ensure vuln_proto.modified is not None (has seconds or nanos)
        proto_modified_dt = None
        if vuln_proto.modified and (vuln_proto.modified.seconds or vuln_proto.modified.nanos):
            proto_modified_dt = vuln_proto.modified.ToDatetime().replace(tzinfo=datetime.UTC) # Ensure tz aware

        if bug_model is None or \
           (bug_model.import_last_modified != proto_modified_dt and proto_modified_dt is not None):
          # Bug is new, or its content (judging by modified timestamp) has changed.
          # Return hash and blob name to trigger update.
          return blob_sha256_hash, blob.name

    return None # No new or changed vulnerabilities found in this blob that require update.


  def _sync_from_previous_commit(self, source_repo: osv.models.SourceRepository,
                                 repo: pygit2.Repository
                                ) -> Tuple[Set[str], Set[str]]:
    """Sync the repository from a previous commit, identifying changed/deleted vulnerability files."""
    changed_files_set: Set[str] = set() # Renamed changed_entries
    deleted_files_set: Set[str] = set() # Renamed deleted_entries

    # Ensure repo.head.target and source_repo.last_synced_hash are valid Oids or resolvable strings
    # pygit2.Repository.walk expects Oid.
    try:
        head_oid = repo.revparse_single(str(repo.head.target)).id # type: ignore[union-attr]
        last_synced_oid = repo.revparse_single(source_repo.last_synced_hash).id if source_repo.last_synced_hash else None
    except pygit2.GitError as e:
        logging.error("Failed to resolve OIDs for diff in repo %s: %s", source_repo.name, e)
        return changed_files_set, deleted_files_set # Return empty sets on error

    # Walker to iterate through commits from HEAD back to last_synced_hash (exclusive)
    walker: pygit2.Walker = repo.walk(head_oid, pygit2.enums.SortMode.TOPOLOGICAL)
    if last_synced_oid:
      walker.hide(last_synced_oid)

    current_commit: pygit2.Commit # Type hint for loop var, renamed commit
    for current_commit in walker:
      # Skip commits made by OSV itself to avoid processing its own changes
      if current_commit.author and current_commit.author.email == osv.models.AUTHOR_EMAIL: # osv.models
        continue

      # Skip commits with a "no update" marker in the message
      if _NO_UPDATE_MARKER in current_commit.message:
        logging.info('Skipping commit %s due to no-update marker.', str(current_commit.id))
        continue

      logging.info('Processing commit %s (author: %s)', str(current_commit.id), current_commit.author.email if current_commit.author else "Unknown")

      # Compare commit with its parents to find changed files
      for parent_commit in current_commit.parents: # parent is pygit2.Commit # Renamed parent
        diff_obj: pygit2.Diff = repo.diff(parent_commit, current_commit) # Renamed diff

        delta_item: pygit2.DiffDelta # Type hint for loop var, renamed delta
        for delta_item in diff_obj:
          # Process old file path (for modifications and deletions)
          if delta_item.old_file and _is_vulnerability_file(source_repo, delta_item.old_file.path):
            if delta_item.status == pygit2.enums.DeltaStatus.DELETED:
              deleted_files_set.add(delta_item.old_file.path)
            else: # MODIFIED, RENAMED, COPIED, etc. -> treat as changed
              changed_files_set.add(delta_item.old_file.path)

          # Process new file path (for additions and modifications where path might change)
          # If file was renamed, old_file.path is old, new_file.path is new.
          # If modified in place, paths are same. If added, old_file is None.
          if delta_item.new_file and _is_vulnerability_file(source_repo, delta_item.new_file.path):
            changed_files_set.add(delta_item.new_file.path)

    return changed_files_set, deleted_files_set

  def _process_updates_git(self, source_repo: osv.models.SourceRepository) -> None:
    """Process updates for a git source_repo."""
    logging.info("Begin processing git updates for source: %s", source_repo.name)

    try:
      repo: pygit2.Repository = self.checkout(source_repo)
    except osv.repos.GitCloneError as e: # osv.repos
        logging.error("Failed to checkout git repo for source %s: %s", source_repo.name, e)
        return # Cannot proceed without repo

    changed_files: Set[str] # Renamed changed_entries
    # deleted_files: Set[str] # Not used in this part of the logic for updates

    if source_repo.last_synced_hash:
      # Syncing from a previous commit: get changed and deleted files.
      # We are only interested in changed_files for triggering updates here.
      # Deleted files are handled by `process_deletions`.
      changed_files, _ = self._sync_from_previous_commit(source_repo, repo)
    else:
      # First sync from scratch: consider all vulnerability files as "changed".
      logging.info('Performing first sync for repo: %s (syncing all files)', source_repo.name)
      changed_files = set()
      # osv.sources.repo_path needed
      repo_disk_path = sources.repo_path(repo) # Renamed
      for dir_root, _, file_names in os.walk(repo_disk_path): # Renamed root, filenames
        for file_name in file_names: # Renamed filename
          full_path = os.path.join(dir_root, file_name)
          relative_path = os.path.relpath(full_path, repo_disk_path) # Renamed
          if _is_vulnerability_file(source_repo, relative_path):
            changed_files.add(relative_path)

    import_failure_logs_list: List[str] = [] # Renamed import_failure_logs

    for changed_file_path in changed_files: # Renamed changed_entry
      # Full path to the file in the local checkout
      # osv.sources.repo_path needed
      local_file_path = os.path.join(sources.repo_path(repo), changed_file_path) # Renamed path
      if not os.path.exists(local_file_path):
        logging.warning('File %s marked as changed but does not exist. Skipping.', local_file_path)
        continue

      try:
        # Attempt to parse to validate structure and get ID for logging if needed.
        # osv.sources.parse_vulnerability needed
        # This will raise if strict validation is on and fails.
        sources.parse_vulnerability(
            local_file_path,
            key_path=source_repo.key_path,
            strict=source_repo.strict_validation and self._strict_validation)
      except sources.KeyPathError: # osv.sources.KeyPathError
        logging.info('OSV entry not found at key_path in %s. Skipping update task.', changed_file_path)
        continue
      except Exception as e: # Catch other parsing/validation errors (e.g., jsonschema.ValidationError)
        logging.error('Failed to parse/validate %s: %s', changed_file_path, e)
        with open(local_file_path, "rb") as f_content:
          file_content_bytes = f_content.read() # Renamed content
        # Infer ID for logging the finding against.
        inferred_bug_id = self._infer_id_from_invalid_data(
            os.path.basename(local_file_path), file_content_bytes) # Renamed bug_id
        self._record_quality_finding(source_repo.name, inferred_bug_id) # Default finding is INVALID_JSON
        import_failure_logs_list.append(f'Failed to parse/validate vulnerability "{changed_file_path}"')
        continue # Skip requesting analysis for invalid files

      # If parsing/validation succeeded, request analysis.
      logging.info('Analysis task triggered for changed file: %s', changed_file_path)
      # osv.sources.sha256 needed
      file_sha256 = sources.sha256(local_file_path) # Renamed original_sha256
      self._request_analysis_external(source_repo, file_sha256, changed_file_path)

    # Update public logs and the last_synced_hash for the source repository.
    # Ensure storage.Client() is created if needed, or pass one in.
    storage_client_instance = storage.Client() # Renamed
    replace_importer_log(storage_client_instance, source_repo.name,
                         self._public_log_bucket, import_failure_logs_list)

    # repo.head.target is an Oid object
    source_repo.last_synced_hash = str(repo.head.target) # type: ignore[union-attr]
    source_repo.put()

    logging.info('Finished processing git updates for source: %s', source_repo.name)


  def _process_updates_bucket(self, source_repo: osv.models.SourceRepository) -> None:
    """Process updates from a GCS bucket source."""
    logging.info("Begin processing GCS bucket for updates: %s", source_repo.name)

    import_time = utcnow() # Consistent timestamp for this import run, renamed

    # Determine last update date to check against blob.updated
    # Default to very old date if never updated or ignoring last import time.
    last_processed_update_time = datetime.datetime.min.replace(tzinfo=datetime.UTC) # Renamed
    if source_repo.last_update_date and not source_repo.ignore_last_import_time:
        last_processed_update_time = source_repo.last_update_date

    # If ignore_last_import_time was true, reset it for next run.
    if source_repo.ignore_last_import_time:
      source_repo.ignore_last_import_time = False
      # This put() might be deferred until after all processing for the source_repo.
      # For now, keeping as is. Consider batching NDB puts.
      source_repo.put()


    storage_client_instance = modify_storage_client_adapters(storage.Client()) # Renamed

    # List blobs in the bucket/prefix
    # Ensure source_repo.bucket is not None
    if not source_repo.bucket:
        logging.error("Source repository %s has no bucket configured.", source_repo.name)
        return

    logging.info('Listing blobs in gs://%s/%s', source_repo.bucket, source_repo.directory_path or "")
    # list_blobs returns an iterator. Convert to list to process all at once or handle iteratively.
    # Original code converted to list.
    all_blobs_in_gcs: List[Blob] = list(storage_client_instance.list_blobs( # Renamed
        source_repo.bucket,
        prefix=source_repo.directory_path, # Can be None
        retry=gcs_retry.DEFAULT_RETRY # Use aliased gcs_retry
    ))

    import_failure_logs_list: List[str] = [] # Renamed

    # Use ThreadPoolExecutor for parallel processing of blobs
    # Each worker needs its own NDB client context.
    # The original _convert_blob_to_vuln created a new client or used existing context.
    # It's better if worker_init sets up NDB context per thread.
    # For now, assuming _convert_blob_to_vuln handles its NDB context.

    # Store results from _convert_blob_to_vuln: List of Optional[Tuple[str, str]]
    # where tuple is (sha256_hash, blob_name)
    processed_blob_results: List[Optional[Tuple[str, str]]] = [] # Renamed converted_vulns

    # NDB client for threads (if not handled by get_context(False))
    # This is tricky with threads and NDB. Each thread needs its own context.
    # The original code passed `datastore_client = ndb.Client()` to submit.
    # This creates a new client per task, which is not ideal.
    # Better: worker_init for ThreadPoolExecutor, or ensure get_context(False) works.
    # For now, let's assume _convert_blob_to_vuln correctly gets/uses an NDB context.

    with concurrent.futures.ThreadPoolExecutor(max_workers=_BUCKET_THREAD_COUNT) as executor:
      logging.info('Submitting %d blobs from %s for parallel processing.', len(all_blobs_in_gcs), source_repo.name)

      # Map blob to future that will return Optional[Tuple[str, str]]
      future_to_blob_map: Dict[concurrent.futures.Future[Optional[Tuple[str, str]]], Blob] = { # Renamed
          executor.submit(self._convert_blob_to_vuln,
                          storage_client_instance, # Pass the main client
                          _ndb_client, # Pass global or correctly scoped client for NDB ops in thread
                          source_repo,
                          current_blob, # Renamed blob
                          last_processed_update_time == datetime.datetime.min.replace(tzinfo=datetime.UTC) # effectively ignore_last_import_time
                         ): current_blob
          for current_blob in all_blobs_in_gcs
      }

      logging.info('Processing results for %d submitted blobs from %s.', len(future_to_blob_map), source_repo.name)
      for future_item in concurrent.futures.as_completed(future_to_blob_map): # Renamed future
        blob_item = future_to_blob_map[future_item] # Renamed blob
        try:
          result_tuple: Optional[Tuple[str, str]] = future_item.result()
          if result_tuple: # If (hash, blob_name) was returned, means update is needed
            processed_blob_results.append(result_tuple)
        except Exception as e: # Catch errors from _convert_blob_to_vuln itself
          logging.error('Error processing blob %s (future result): %s', blob_item.name, e)
          # If _convert_blob_to_vuln doesn't catch its own errors for parsing, this is a fallback.
          # It's better if _convert_blob_to_vuln handles its errors and returns None.
          # Here, we assume future.result() might raise if the task itself failed before returning.
          if blob_item.name: # Ensure blob_item.name is not None
            # Try to get blob_bytes again for infer_id, or pass None if download failed
            blob_bytes_for_infer: Optional[bytes] = None
            try:
                blob_to_download = Blob(blob_item.name, blob_item.bucket, generation=None)
                blob_bytes_for_infer = blob_to_download.download_as_bytes(client=storage_client_instance)
            except Exception: # Ignore download error for inferring ID
                pass
            inferred_id = self._infer_id_from_invalid_data(blob_item.name, blob_bytes_for_infer or b"")
            self._record_quality_finding(source_repo.name, inferred_id)
            import_failure_logs_list.append(f'Failed to process blob "{blob_item.name}" (exception in task).')


      # Request analysis for blobs that need update
      for blob_hash_val, blob_name_val in processed_blob_results: # Renamed cv
          if blob_hash_val and blob_name_val: # Ensure both are valid
            logging.info('Requesting analysis of GCS blob: %s/%s', source_repo.bucket, blob_name_val)
            self._request_analysis_external(source_repo, blob_hash_val, blob_name_val)

      # Update logs and source repo metadata
      replace_importer_log(storage_client_instance, source_repo.name,
                           self._public_log_bucket, import_failure_logs_list)
      source_repo.last_update_date = import_time # Record time of this import run
      source_repo.put()

      logging.info('Finished processing GCS bucket for updates: %s', source_repo.name)


  def _process_deletions_bucket(self,
                                source_repo: osv.models.SourceRepository,
                                threshold: float = 10.0) -> None:
    """Process deletions from a GCS bucket source."""
    logging.info('Begin processing GCS bucket for deletions: %s', source_repo.name)

    # Define a NamedTuple for storing ID and source path together.
    class VulnAndSourcePath(NamedTuple):
        id: str
        path: str

    # Get all non-withdrawn Bug IDs and their source_id paths from Datastore for this source.
    # osv.models.Bug needed
    datastore_bug_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query( # Renamed query
        osv.models.Bug.source == source_repo.name,
        osv.models.Bug.withdrawn == None # Filter for non-withdrawn bugs # type: ignore[comparison-overlap]
    )
    # Fetch only key and source_id to optimize
    # Projection queries return entities with only projected properties populated.
    # Here, to get key.id() and source_id, we might not need full projection if key is enough.
    # If source_id is needed directly, it must be projected.
    # Bug.source_id format is "source_name:path_to_vuln"

    vuln_ids_and_paths_in_datastore: List[VulnAndSourcePath] = [] # Renamed
    logging.info('Retrieving current non-withdrawn Bugs from Datastore for source %s...', source_repo.name)

    current_bug_in_db: osv.models.Bug # Type hint for loop var, renamed result, r
    # Iterating over full entities to access source_id and key.id()
    for current_bug_in_db in datastore_bug_query: # Removed .fetch() to iterate
        if current_bug_in_db.id() and current_bug_in_db.source_id:
            # source_id is like "SOURCE_NAME:PATH_IN_SOURCE"
            # We need PATH_IN_SOURCE for comparison with blob names.
            # osv.sources.parse_source_id needed
            _, path_in_source = sources.parse_source_id(current_bug_in_db.source_id)
            vuln_ids_and_paths_in_datastore.append(VulnAndSourcePath(id=current_bug_in_db.id(), path=path_in_source))

    logging.info('Found %d non-withdrawn Bugs for %s in Datastore.',
                 len(vuln_ids_and_paths_in_datastore), source_repo.name)


    storage_client_instance = storage.Client() # Renamed
    # Get all current vulnerability IDs from GCS blobs for this source.
    if not source_repo.bucket:
        logging.error("Source repository %s has no bucket configured for deletion processing.", source_repo.name)
        return

    logging.info('Listing all blobs in gs://%s/%s for deletion check.',
                 source_repo.bucket, source_repo.directory_path or "")
    all_gcs_blobs: List[Blob] = list(storage_client_instance.list_blobs( # Renamed
        source_repo.bucket,
        prefix=source_repo.directory_path, # Can be None
        retry=gcs_retry.DEFAULT_RETRY # Use aliased gcs_retry
    ))

    import_failure_logs_list: List[str] = [] # Renamed

    # Set of all vulnerability IDs found in GCS.
    vuln_ids_present_in_gcs: Set[str] = set() # Renamed

    with concurrent.futures.ThreadPoolExecutor(max_workers=_BUCKET_THREAD_COUNT) as executor:
      logging.info('Parallel-parsing %d blobs from GCS for %s to get current IDs.',
                   len(all_gcs_blobs), source_repo.name)

      # Map future to blob name for logging/error context
      future_to_blob_name_map: Dict[concurrent.futures.Future[Optional[List[str]]], str] = { # Renamed
          executor.submit(self._vuln_ids_from_gcs_blob, storage_client_instance,
                          source_repo, current_blob): current_blob.name # Renamed blob
          for current_blob in all_gcs_blobs if current_blob.name # Ensure name is not None
      }

      for future_item in concurrent.futures.as_completed(future_to_blob_name_map): # Renamed
        blob_name_processed = future_to_blob_name_map[future_item] # Renamed blob
        try:
          ids_from_blob: Optional[List[str]] = future_item.result()
          if ids_from_blob:
            vuln_ids_present_in_gcs.update(ids_from_blob)
        except Exception as e: # Catch errors from _vuln_ids_from_gcs_blob task itself
          logging.error('Error parsing GCS blob %s during deletion check: %s', blob_name_processed, e)
          import_failure_logs_list.append(
              f'Failed to parse GCS blob "{blob_name_processed}" during deletion check.')
          # Optionally record a finding if we can infer an ID.
          # For deletions, focus is on what's missing vs what's invalid.

    logging.info('Found %d unique vulnerability IDs in GCS for source %s.',
                 len(vuln_ids_present_in_gcs), source_repo.name)

    # Determine which vulns in Datastore are no longer in GCS
    vulns_to_be_deleted: List[VulnAndSourcePath] = [ # Renamed
        vas_item for vas_item in vuln_ids_and_paths_in_datastore # Renamed v
        if vas_item.id not in vuln_ids_present_in_gcs
    ]

    logging.info('%d Bugs in Datastore are considered deleted from GCS for %s.',
                 len(vulns_to_be_deleted), source_repo.name)

    if not vuln_ids_and_paths_in_datastore: # Avoid division by zero if no vulns were in DB
        logging.info("No existing non-withdrawn vulnerabilities in Datastore for %s to compare against.", source_repo.name)
    elif len(vulns_to_be_deleted) / len(vuln_ids_and_paths_in_datastore) * 100 >= threshold:
      logging.error(
          'Deletion safety threshold exceeded for %s: %d out of %d bugs (%:.2f%%) would be deleted. Aborting.',
          source_repo.name, len(vulns_to_be_deleted), len(vuln_ids_and_paths_in_datastore),
          (len(vulns_to_be_deleted) / len(vuln_ids_and_paths_in_datastore) * 100)
      )
      # Log the list of vulns that would have been deleted for investigation
      deleted_ids_log = [v_item.id for v_item in vulns_to_be_deleted] # Renamed
      logging.info('Vulnerabilities that would have been marked for deletion: %s', deleted_ids_log)
      # Update public log with any parsing failures encountered even if aborting deletion.
      replace_importer_log(storage_client_instance, source_repo.name,
                           self._public_log_bucket, import_failure_logs_list)
      return # Abort deletion process

    if not vulns_to_be_deleted:
      logging.info('No GCS bug deletions to process for %s.', source_repo.name)
    else:
      # Request deletion (which means marking as withdrawn by sending an update task)
      for vuln_to_delete_info in vulns_to_be_deleted: # Renamed v
        logging.info('Requesting deletion (withdrawal) for Bug ID %s (path %s) from source %s.',
                     vuln_to_delete_info.id, vuln_to_delete_info.path, source_repo.name)
        # original_sha256='' indicates content is gone or to be ignored.
        # path is relative path within source_repo.
        self._request_analysis_external(
            source_repo, original_sha256='', path=vuln_to_delete_info.path, deleted=True)

    # Update public log even if no deletions, to clear previous errors if any.
    replace_importer_log(storage_client_instance, source_repo.name,
                         self._public_log_bucket, import_failure_logs_list)
    logging.info("Finished processing GCS bucket for deletions: %s", source_repo.name)


  def _process_updates_rest(self, source_repo: osv.models.SourceRepository) -> None:
    """Process updates from a REST API source."""
    logging.info('Begin processing REST API for updates: %s', source_repo.name)

    # Determine the effective last update date for comparison
    last_processed_update_dt = datetime.datetime.min.replace(tzinfo=datetime.UTC) # Renamed
    if source_repo.last_update_date and not source_repo.ignore_last_import_time:
        last_processed_update_dt = source_repo.last_update_date

    if source_repo.ignore_last_import_time: # Reset flag after use
      source_repo.ignore_last_import_time = False
      source_repo.put() # Persist change to flag

    # Setup requests session with retries
    session = requests.Session() # Renamed s
    retry_strategy = Retry( # Renamed
        total=3, status_forcelist=[502, 503, 504], backoff_factor=1)
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount('http://', adapter)
    session.mount('https://', adapter)

    # Make HEAD request to check Last-Modified header
    head_response: requests.Response # Renamed request
    try:
      # Ensure source_repo.rest_api_url is not None
      if not source_repo.rest_api_url:
          logging.error("REST API URL not configured for source: %s", source_repo.name)
          return
      head_response = session.head(source_repo.rest_api_url, timeout=_TIMEOUT_SECONDS)
      head_response.raise_for_status() # Check for HTTP errors
    except requests.exceptions.RequestException as e:
      logging.exception('Exception during HEAD request to REST API %s: %s', source_repo.rest_api_url, e)
      return

    # Parse Last-Modified header from HEAD response
    endpoint_last_modified_dt: Optional[datetime.datetime] = None # Renamed request_last_modified
    last_modified_header: Optional[str] = head_response.headers.get('Last-Modified') # Renamed
    if last_modified_header:
      try:
        endpoint_last_modified_dt = datetime.datetime.strptime(
            last_modified_header, _HTTP_LAST_MODIFIED_FORMAT).replace(tzinfo=datetime.UTC)
        if endpoint_last_modified_dt <= last_processed_update_dt:
          logging.info('No changes in REST API %s since last update (%s <= %s).',
                       source_repo.rest_api_url, endpoint_last_modified_dt, last_processed_update_dt)
          return
      except ValueError:
        logging.error('Invalid Last-Modified header format from %s: "%s"',
                      source_repo.rest_api_url, last_modified_header)
        # Proceed to GET if Last-Modified is unparsable, but log it.

    # GET the full list of vulnerabilities if needed
    get_response: requests.Response # Renamed request
    try:
      get_response = session.get(source_repo.rest_api_url, timeout=_TIMEOUT_SECONDS)
      get_response.raise_for_status()
    except requests.exceptions.RequestException as e:
      logging.exception('Exception during GET request to REST API %s: %s', source_repo.rest_api_url, e)
      return

    # Parse vulnerabilities from the GET response
    # osv.sources.parse_vulnerabilities_from_data needed
    try:
      # Ensure source_repo.extension is not None
      file_extension = source_repo.extension or '.json' # Default if None
      vulns_from_rest: List[vulnerability_pb2.Vulnerability] = sources.parse_vulnerabilities_from_data( # Renamed vulns
          get_response.text, # Assuming text response (JSON or YAML)
          file_extension,
          strict=source_repo.strict_validation and self._strict_validation)
    except Exception as e: # Catch parsing/validation errors
        logging.error("Failed to parse vulnerability data from REST API %s: %s", source_repo.rest_api_url, e)
        # Consider recording a general finding for the source if parsing the main list fails.
        return

    # Track the latest modification time seen among the vulnerabilities processed.
    latest_vuln_modified_dt: datetime.datetime = last_processed_update_dt # Renamed vulns_last_modified

    logging.info('Processing %d records from REST API %s', len(vulns_from_rest), source_repo.rest_api_url)
    import_failure_logs_list: List[str] = [] # Renamed

    for vuln_proto in vulns_from_rest: # Renamed vuln
      # Ensure vuln_proto.modified is valid and convert to datetime
      proto_modified_dt = None
      if vuln_proto.modified and (vuln_proto.modified.seconds or vuln_proto.modified.nanos):
          proto_modified_dt = vuln_proto.modified.ToDatetime().replace(tzinfo=datetime.UTC)

      if not proto_modified_dt:
          logging.warning("Vulnerability %s from REST API has no modified timestamp. Skipping.", vuln_proto.id)
          continue

      # Update overall latest modification time seen
      latest_vuln_modified_dt = max(latest_vuln_modified_dt, proto_modified_dt)

      # Skip if this vulnerability hasn't been modified since last import run
      if proto_modified_dt <= last_processed_update_dt:
        continue

      # Fetch individual vulnerability data if source_repo.link is defined
      # This implies the main list is a summary, and details are fetched per-entry.
      # This part seems to assume that `source_repo.link + vuln.id + source_repo.extension` is the detailed URL.
      # This might not always be the case. If the main list already contains full data, this is redundant.
      # For now, following original logic.
      if source_repo.link:
          # Ensure source_repo.link and source_repo.extension are not None
          detailed_vuln_url = (source_repo.link or "") + vuln_proto.id + (source_repo.extension or '.json')
          try:
            single_vuln_response = session.get(detailed_vuln_url, timeout=_TIMEOUT_SECONDS) # Renamed
            single_vuln_response.raise_for_status()

            # Validate the individually fetched data
            # This uses _parse_vulnerability_from_dict which expects dict, not text/bytes.
            # And key_path is used. This seems to mix patterns.
            # For now, assuming the detailed fetch gives richer data that needs re-parsing/validation.
            # This path needs careful review of how REST sources are structured.
            # Assuming the detailed response is JSON and needs parsing.
            detailed_data_dict = single_vuln_response.json()
            # osv.sources.parse_vulnerability_from_dict
            sources.parse_vulnerability_from_dict(
                detailed_data_dict,
                key_path=source_repo.key_path, # key_path might be for nested structures
                strict=source_repo.strict_validation and self._strict_validation)

            # If valid, request analysis using its content's hash and path (vuln.id + extension)
            # osv.sources.sha256_bytes
            content_bytes_for_hash = single_vuln_response.text.encode('utf-8')
            data_sha256 = sources.sha256_bytes(content_bytes_for_hash)
            path_for_request = vuln_proto.id + (source_repo.extension or '.json')

            logging.info('Requesting analysis of REST record (detailed fetch): %s', path_for_request)
            self._request_analysis_external(source_repo, data_sha256, path_for_request)

          except sources.KeyPathError: # osv.sources.KeyPathError
            logging.info('Detailed REST entry for %s does not have an OSV entry at key_path. Skipping.', vuln_proto.id)
          except Exception as e: # Catch errors from detailed fetch/parse
            logging.exception('Failed to process detailed REST entry for %s: %s', vuln_proto.id, e)
            # Attempt to infer ID for finding, using original summary data if detailed fetch failed.
            # This inference logic might be inexact if detailed fetch was the true source.
            inferred_id_for_finding = self._infer_id_from_invalid_data(
                detailed_vuln_url, single_vuln_response.content if 'single_vuln_response' in locals() else b"")
            self._record_quality_finding(source_repo.name, inferred_id_for_finding)
            import_failure_logs_list.append(f'Failed to process detailed REST entry "{vuln_proto.id}"')
      else:
          # If no source_repo.link, assume vuln_proto from main list is complete.
          # Need its path/name and hash. Path is effectively vuln.id + extension.
          # Hash would be of its representation if it were a file.
          # This part is underspecified if main list entries are to be hashed directly.
          # For now, assume if no link, we can't get a hash easily for _request_analysis_external.
          # This might mean such REST sources are not fully supported by this path.
          logging.warning("REST source %s has no item link; cannot process individual item hash for %s.",
                          source_repo.name, vuln_proto.id)
          # Alternative: if the main list *is* the source of truth and items are full vulns,
          # then `osv.sha256_bytes(json.dumps(MessageToDict(vuln_proto)).encode())` could be hash.
          # Path would be `vuln_proto.id + source_repo.extension`.
          # This depends on whether `_request_analysis_external` needs a real file path or just an identifier.
          # Given current structure, let's log and skip if no link for individual hash.
          import_failure_logs_list.append(f'Skipped REST entry "{vuln_proto.id}" due to no source_repo.link for hash.')


    replace_importer_log(storage.Client(), source_repo.name,
                         self._public_log_bucket, import_failure_logs_list)

    # Update last_update_date: use endpoint's Last-Modified if valid and later, else use latest vuln modified.
    if endpoint_last_modified_dt and endpoint_last_modified_dt > latest_vuln_modified_dt:
        source_repo.last_update_date = endpoint_last_modified_dt
    else:
        source_repo.last_update_date = latest_vuln_modified_dt
    source_repo.put()

    logging.info('Finished processing REST API for updates: %s', source_repo.name)


  def _process_deletions_rest(self, source_repo: osv.models.SourceRepository) -> None:
    """Process deletions from a REST API source."""
    # This requires comparing all IDs in NDB for this source vs. all IDs currently in REST API.
    # The current _process_updates_rest fetches all from REST. That list could be used.
    # However, this is complex if the REST API doesn't provide a full list reliably or is paginated.
    # Original code had NotImplementedError.
    logging.warning("_process_deletions_rest is not yet implemented for source: %s", source_repo.name)
    raise NotImplementedError # Explicitly keep as not implemented

  def validate_source_repo(self, source_repo: osv.models.SourceRepository) -> None:
    """Validate the source_repo configuration for correctness."""
    if source_repo.link and not source_repo.link.endswith('/'): # Ensure trailing slash if link exists
      # This could be an error or auto-correction. Original raises ValueError.
      raise ValueError(f'Source repository link for {source_repo.name} must end with /')

  def process_updates(self, source_repo: osv.models.SourceRepository) -> None:
    """Process source record changes and updates based on source type."""
    # osv.models.SourceRepositoryType needed
    if source_repo.type == osv.models.SourceRepositoryType.GIT:
      self._process_updates_git(source_repo)
    elif source_repo.type == osv.models.SourceRepositoryType.BUCKET:
      self._process_updates_bucket(source_repo)
    elif source_repo.type == osv.models.SourceRepositoryType.REST_ENDPOINT:
      self._process_updates_rest(source_repo)
    else:
      logging.error('Invalid source repository type for %s: %d', source_repo.name, source_repo.type)


  def process_deletions(self, source_repo: osv.models.SourceRepository) -> None:
    """Process source record deletions by withdrawing them, based on source type."""
    # osv.models.SourceRepositoryType needed
    if source_repo.type == osv.models.SourceRepositoryType.GIT:
      # TODO: Implement deletion processing for Git sources.
      logging.warning("Deletion processing for GIT sources is not yet fully implemented.")
      return
    elif source_repo.type == osv.models.SourceRepositoryType.BUCKET:
      self._process_deletions_bucket(source_repo, self._deletion_safety_threshold_pct)
    elif source_repo.type == osv.models.SourceRepositoryType.REST_ENDPOINT:
      # TODO: Implement deletion processing for REST API sources.
      logging.warning("Deletion processing for REST_ENDPOINT sources is not yet fully implemented.")
      return
    else:
      logging.error('Invalid source repository type for deletion processing %s: %d',
                    source_repo.name, source_repo.type)


  def process_oss_fuzz(self, oss_fuzz_source_repo: osv.models.SourceRepository) -> None: # Renamed
    """Process OSS-Fuzz source data: export to Git, then to GCS bucket."""
    logging.info("Processing OSS-Fuzz source: %s", oss_fuzz_source_repo.name)
    try:
      repo: pygit2.Repository = self.checkout(oss_fuzz_source_repo)
    except osv.repos.GitCloneError as e: # osv.repos
        logging.error("Failed to checkout OSS-Fuzz repo for source %s: %s", oss_fuzz_source_repo.name, e)
        return

    self.schedule_regular_updates(repo, oss_fuzz_source_repo)
    self.import_new_oss_fuzz_entries(repo, oss_fuzz_source_repo)
    self.export_oss_fuzz_to_bucket()
    logging.info("Finished processing OSS-Fuzz source: %s", oss_fuzz_source_repo.name)


  def export_oss_fuzz_to_bucket(self) -> None:
    """Export all public OSS-Fuzz vulnerabilities from NDB to a GCS bucket."""
    logging.info("Exporting public OSS-Fuzz vulnerabilities to GCS bucket: %s", self._oss_fuzz_export_bucket)
    storage_client_instance = storage.Client() # Renamed
    # Ensure bucket name is not None or empty string
    if not self._oss_fuzz_export_bucket:
        logging.error("OSS-Fuzz export bucket name is not configured.")
        return
    bucket_obj: Bucket = storage_client_instance.bucket(self._oss_fuzz_export_bucket) # Renamed

    # Inner helper function for concurrent execution
    def _export_single_oss_fuzz_vuln(vulnerability_proto: vulnerability_pb2.Vulnerability, # Renamed
                                     testcase_id_str: str, # Renamed
                                     issue_id_str: Optional[str]) -> None: # Renamed
      """Exports a single OSS-Fuzz vulnerability to GCS."""
      try:
        # Export by testcase ID (source_id part)
        blob_testcase: Blob = bucket_obj.blob(f'testcase/{testcase_id_str}.json') # Renamed
        # osv.models.vulnerability_to_dict needed
        vuln_dict_data: Dict[str,Any] = osv.models.vulnerability_to_dict(vulnerability_proto) # Renamed
        blob_testcase.upload_from_string(json.dumps(vuln_dict_data), retry=gcs_retry.DEFAULT_RETRY) # Use aliased retry

        # If issue_id (Buganizer ID) exists, also export by that ID
        if issue_id_str:
          blob_issue: Blob = bucket_obj.blob(f'issue/{issue_id_str}.json') # Renamed
          blob_issue.upload_from_string(json.dumps(vuln_dict_data), retry=gcs_retry.DEFAULT_RETRY)
      except Exception: # Catch broad exceptions during export of a single bug
        logging.exception('Failed to export OSS-Fuzz vuln (testcase: %s, issue: %s)',
                          testcase_id_str, issue_id_str)

    # Query for all public OSS-Fuzz bugs
    # osv.models.Bug needed
    oss_fuzz_bugs_query: ndb.Query[osv.models.Bug] = osv.models.Bug.query( # Renamed
        osv.models.Bug.ecosystem == 'OSS-Fuzz', # Assuming direct ecosystem filter is okay
        osv.models.Bug.public == True # noqa: E712
    )

    with concurrent.futures.ThreadPoolExecutor(max_workers=_EXPORT_WORKERS) as executor:
      current_bug_model: osv.models.Bug # Type hint for loop var, renamed bug
      for current_bug_model in oss_fuzz_bugs_query:
        if not current_bug_model.public: # Double check, though query should handle
          continue

        # Ensure source_id is present
        if not current_bug_model.source_id:
            logging.warning("OSS-Fuzz bug %s missing source_id, cannot export by testcase_id.", current_bug_model.id())
            continue

        # osv.sources.parse_source_id needed
        _, source_id_part = sources.parse_source_id(current_bug_model.source_id) # Testcase ID part

        # Submit export task to thread pool
        # to_vulnerability() is synchronous. If it's too slow, consider making it async too.
        executor.submit(_export_single_oss_fuzz_vuln,
                        current_bug_model.to_vulnerability(), # Get full Vulnerability proto
                        source_id_part,
                        current_bug_model.issue_id) # issue_id can be None
    logging.info("Finished exporting OSS-Fuzz vulnerabilities to GCS.")


def main() -> None: # main usually doesn't return a value, or 0 for success / non-0 for error
  parser = argparse.ArgumentParser(description='Importer')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument(
      '--public_log_bucket',
      help="Public logging bucket",
      default=DEFAULT_PUBLIC_LOGGING_BUCKET)
  parser.add_argument('--ssh_key_public', help='Public SSH key path')
  parser.add_argument('--ssh_key_private', help='Private SSH key path')
  parser.add_argument(
      '--strict_validation',
      action='store_true',
      help='Fail to import entries that does not pass validation',
      default=False)
  parser.add_argument(
      '--delete',
      action='store_true',
      help=('Bypass importing and propagate record deletions from source to '
            'Datastore'),
      default=False)
  parser.add_argument(
      '--delete_threshold_pct',
      type=float,
      help='More than this percent of records for a given source '
      'being deleted triggers an error',
      default=10)
  args = parser.parse_args()

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  # Temp files are on the persistent local SSD,
  # and they do not get removed when GKE sends a SIGTERM to stop the pod.
  # Manually clear the tmp_dir folder of any leftover files
  # TODO(michaelkedar): use an ephemeral disk for temp storage.
  if os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  importer = Importer(args.ssh_key_public, args.ssh_key_private, args.work_dir,
                      args.public_log_bucket, _OSS_FUZZ_EXPORT_BUCKET,
                      args.strict_validation, args.delete,
                      args.delete_threshold_pct)
  importer.run()


if __name__ == '__main__':
  atexit.register(log_run_duration, time.time())
  osv.logs.setup_gcp_logging('importer')
  _ndb_client = ndb.Client()
  with _ndb_client.context():
    main()
