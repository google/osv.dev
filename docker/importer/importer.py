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
"""OSV Importer."""

# TODO: Refactor per
# https://github.com/google/osv.dev/pull/2030#discussion_r1513861856

import argparse
import concurrent.futures
from collections import namedtuple
import datetime
import json
import logging
import os
import requests
import shutil
import threading
import time
import atexit
from typing import List, Tuple, Optional

from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud import storage
from google.cloud.storage import retry
import pygit2.enums

import osv
import osv.logs

DEFAULT_WORK_DIR = '/work'
DEFAULT_PUBLIC_LOGGING_BUCKET = 'osv-public-import-logs'

_BUG_REDO_DAYS = 14
_TASKS_TOPIC = 'tasks'
_OSS_FUZZ_EXPORT_BUCKET = 'oss-fuzz-osv-vulns'
_EXPORT_WORKERS = 32
_NO_UPDATE_MARKER = 'OSV-NO-UPDATE'
_BUCKET_THREAD_COUNT = 20
_HTTP_LAST_MODIFIED_FORMAT = '%a, %d %b %Y %H:%M:%S %Z'
_TIMEOUT_SECONDS = 60

_client_store = threading.local()


def _is_vulnerability_file(source_repo, file_path):
  """Return whether or not the file is a Vulnerability entry."""
  if (source_repo.directory_path and
      not file_path.startswith(source_repo.directory_path.rstrip('/') + '/')):
    return False

  if source_repo.ignore_file(file_path):
    return False

  return file_path.endswith(source_repo.extension)


def aestnow() -> datetime:
  """Get the current AEST time"""
  # - First make datetime timezone aware
  # - Then set timezone to AEST without DST (+10)
  # - Then make datetime timezone unaware again to keep
  #   compatibility with ndb
  return utcnow().replace(tzinfo=datetime.timezone.utc).astimezone(
      datetime.timezone(datetime.timedelta(hours=10))).replace(tzinfo=None)


def utcnow():
  """utcnow() for mocking."""
  return datetime.datetime.utcnow()


def replace_importer_log(client: storage.Client, source_name: str,
                         bucket_name: str, import_failure_logs: List[str]):
  """Replace the public importer logs with the new one."""
  bucket: storage.Bucket = client.bucket(bucket_name)
  upload_string = '--- ' + datetime.datetime.utcnow().isoformat() + ' ---\n'
  upload_string += '\n'.join(import_failure_logs)
  bucket.blob(source_name).upload_from_string(
      upload_string, retry=retry.DEFAULT_RETRY)


def log_run_duration(start: float):
  """Log the elapsed wallclock duration at the end of the program.

  This enables a log-based metric to be created.

  Args:
    start: the time the program started.
  """
  elapsed = time.time() - start
  logging.info('Importer run duration: %d', elapsed)


class Importer:
  """Importer."""

  def __init__(self,
               ssh_key_public_path,
               ssh_key_private_path,
               work_dir,
               public_log_bucket,
               oss_fuzz_export_bucket,
               strict_validation: bool,
               delete: bool,
               deletion_safety_threshold_pct: float = 10.0):
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path
    self._work_dir = work_dir
    self._publisher = pubsub_v1.PublisherClient()
    project = os.environ['GOOGLE_CLOUD_PROJECT']
    self._tasks_topic = self._publisher.topic_path(project, _TASKS_TOPIC)
    self._public_log_bucket = public_log_bucket
    self._oss_fuzz_export_bucket = oss_fuzz_export_bucket

    self._sources_dir = os.path.join(self._work_dir, 'sources')
    self._strict_validation = strict_validation
    self._delete = delete
    self._deletion_safety_threshold_pct = deletion_safety_threshold_pct
    os.makedirs(self._sources_dir, exist_ok=True)

  def _git_callbacks(self, source_repo):
    """Get git auth callbacks."""
    return osv.GitRemoteCallback(source_repo.repo_username,
                                 self._ssh_key_public_path,
                                 self._ssh_key_private_path)

  def _request_analysis(self, bug, source_repo, repo):
    """Request analysis."""
    if bug.source_of_truth == osv.SourceOfTruth.SOURCE_REPO:
      path = osv.source_path(source_repo, bug)
      file_path = os.path.join(osv.repo_path(repo), path)
      if not os.path.exists(file_path):
        logging.info(
            'Skipping analysis for %s as the source file no longer exists.',
            path)
        return

      original_sha256 = osv.sha256(file_path)
      self._request_analysis_external(source_repo, original_sha256, path)
    else:
      self._request_internal_analysis(bug)

  def _request_analysis_external(self,
                                 source_repo,
                                 original_sha256,
                                 path,
                                 deleted=False):
    """Request analysis."""
    self._publisher.publish(
        self._tasks_topic,
        data=b'',
        type='update',
        source=source_repo.name,
        path=path,
        original_sha256=original_sha256,
        deleted=str(deleted).lower(),
        req_timestamp=str(int(time.time())))

  def _request_internal_analysis(self, bug):
    """Request internal analysis."""
    self._publisher.publish(
        self._tasks_topic,
        data=b'',
        type='impact',
        source_id=bug.source_id,
        allocated_id=bug.key.id(),
        req_timestamp=str(int(time.time())))

  def run(self):
    """Run importer."""
    for source_repo in osv.SourceRepository.query():
      if not self._delete and source_repo.name == 'oss-fuzz':
        self.process_oss_fuzz(source_repo)

      self.validate_source_repo(source_repo)
      if not self._delete:
        self.process_updates(source_repo)
      if self._delete:
        self.process_deletions(source_repo)

  def checkout(self, source_repo):
    """Check out a source repo."""
    return osv.ensure_updated_checkout(
        source_repo.repo_url,
        os.path.join(self._sources_dir, source_repo.name),
        git_callbacks=self._git_callbacks(source_repo),
        branch=source_repo.repo_branch)

  def import_new_oss_fuzz_entries(self, repo, oss_fuzz_source):
    """Import new entries."""
    exported = []
    for bug in osv.Bug.query(
        osv.Bug.source_of_truth == osv.SourceOfTruth.INTERNAL):
      if bug.status != osv.BugStatus.PROCESSED:
        continue

      if not bug.public:
        continue

      # We don't index this as INTERNAL generally implies OSS-Fuzz anyway (at
      # time of writing).
      source_name, _ = osv.parse_source_id(bug.source_id)
      if source_name != oss_fuzz_source.name:
        continue

      vulnerability_path = os.path.join(
          osv.repo_path(repo), osv.source_path(oss_fuzz_source, bug))
      os.makedirs(os.path.dirname(vulnerability_path), exist_ok=True)
      if os.path.exists(vulnerability_path):
        continue

      logging.info('Writing %s', bug.key.id())
      osv.write_vulnerability(bug.to_vulnerability(), vulnerability_path)
      # The source of truth is now this yaml file.
      bug.source_of_truth = osv.SourceOfTruth.SOURCE_REPO
      exported.append(bug)

    # Commit Vulnerability changes back to the oss-fuzz source repository.
    repo.index.add_all()
    diff = repo.index.diff_to_tree(repo.head.peel().tree)
    if not diff:
      logging.info('No new entries, skipping committing.')
      return

    logging.info('Committing and pushing new entries')
    if osv.push_source_changes(repo, 'Import from OSS-Fuzz',
                               self._git_callbacks(oss_fuzz_source)):
      ndb.put_multi(exported)

  def schedule_regular_updates(self, repo, source_repo: osv.SourceRepository):
    """Schedule regular updates."""
    aest_time_now = aestnow()

    if (source_repo.last_update_date and
        # OSV devs are mostly located in australia,
        # so only schedule update near midnight sydney time
        source_repo.last_update_date.date() >= aest_time_now.date()):
      return

    for bug in osv.Bug.query(
        osv.Bug.status == osv.BugStatus.PROCESSED,
        osv.Bug.is_fixed == False,  # pylint: disable=singleton-comparison
        osv.Bug.source == source_repo.name):
      self._request_analysis(bug, source_repo, repo)

    # yapf: disable
    # Perform a re-analysis on existing oss-fuzz bugs for a period of time,
    # more vulnerable releases might be made even though fixes have
    # already been merged into master/main
    cutoff_time = aest_time_now - datetime.timedelta(days=_BUG_REDO_DAYS)
    query = osv.Bug.query(osv.Bug.status == osv.BugStatus.PROCESSED,
                          osv.Bug.source == source_repo.name,
                          osv.Bug.timestamp >= cutoff_time)
    # yapf: enable

    for bug in query:
      logging.info('Re-requesting impact for %s.', bug.key.id())
      if not bug.is_fixed:
        # Previous query already requested impact tasks for unfixed bugs.
        continue

      self._request_analysis(bug, source_repo, repo)

    source_repo.last_update_date = aest_time_now
    source_repo.put()

  def _vuln_ids_from_gcs_blob(self, client: storage.Client,
                              source_repo: osv.SourceRepository,
                              blob: storage.Blob) -> Optional[Tuple[str]]:
    """Returns a list of the vulnerability IDs from a parsable OSV file in GCS.

    Usually an OSV file has a single vulnerability in it, but it is permissible
    to have more than one, hence it returns a list.

    This is runnable in parallel using concurrent.futures.ThreadPoolExecutor

    Args:
      client: a storage.Client() to use for retrieval of the blob
      source_repo: the osv.SourceRepository the blob relates to
      blob: the storage.Blob object to operate on

    Returns:
      a list of one or more vulnerability IDs (from the Vulnerability proto) or
      None when the blob has an unexpected name or fails to parse
    """
    if not _is_vulnerability_file(source_repo, blob.name):
      return None

    # Download in a blob generation agnostic way to cope with the blob
    # changing between when it was listed and now (if the generation doesn't
    # match, retrieval fails otherwise).
    blob_bytes = storage.Blob(
        blob.name, blob.bucket, generation=None).download_as_bytes(client)

    vuln_ids = []
    try:
      vulns = osv.parse_vulnerabilities_from_data(
          blob_bytes,
          os.path.splitext(blob.name)[1],
          strict=self._strict_validation)
    except Exception as e:
      logging.error('Failed to parse vulnerability %s: %s', blob.name, e)
      return None
    for vuln in vulns:
      vuln_ids.append(vuln.id)
    return vuln_ids

  def _sync_from_previous_commit(self, source_repo, repo):
    """Sync the repository from the previous commit.

    This was refactored out of _process_updates_git() due to excessive
    indentation.

    Args:
      source_repo: the Git source repository.
      repo: the checked out Git source repository.

    Returns:
      changed_entries: the set of repository paths that have changed.
      deleted_entries: the set of repository paths that have been deleted.
    """
    changed_entries = set()
    deleted_entries = set()

    walker = repo.walk(repo.head.target, pygit2.enums.SortMode.TOPOLOGICAL)
    walker.hide(source_repo.last_synced_hash)

    for commit in walker:
      if commit.author.email == osv.AUTHOR_EMAIL:
        continue

      if _NO_UPDATE_MARKER in commit.message:
        logging.info('Skipping commit %s as no update marker found.', commit.id)
        continue

      logging.info('Processing commit %s from %s', commit.id,
                   commit.author.email)

      for parent in commit.parents:
        diff = repo.diff(parent, commit)
        for delta in diff.deltas:
          if delta.old_file and _is_vulnerability_file(source_repo,
                                                       delta.old_file.path):
            if delta.status == pygit2.enums.DeltaStatus.DELETED:
              deleted_entries.add(delta.old_file.path)
              continue

            changed_entries.add(delta.old_file.path)

          if delta.new_file and _is_vulnerability_file(source_repo,
                                                       delta.new_file.path):
            changed_entries.add(delta.new_file.path)

    return changed_entries, deleted_entries

  def _process_updates_git(self, source_repo: osv.SourceRepository):
    """Process updates for a git source_repo."""
    logging.info("Begin processing git: %s", source_repo.name)

    repo = self.checkout(source_repo)

    # Get list of changed files since last sync.
    changed_entries = set()

    if source_repo.last_synced_hash:
      # Syncing from a previous commit.
      changed_entries, _ = self._sync_from_previous_commit(source_repo, repo)

    else:
      # First sync from scratch.
      logging.info('Syncing repo from scratch')
      for root, _, filenames in os.walk(osv.repo_path(repo)):
        for filename in filenames:
          path = os.path.join(root, filename)
          rel_path = os.path.relpath(path, osv.repo_path(repo))
          if _is_vulnerability_file(source_repo, rel_path):
            changed_entries.add(rel_path)

    import_failure_logs = []
    # Create tasks for changed files.
    for changed_entry in changed_entries:
      path = os.path.join(osv.repo_path(repo), changed_entry)
      if not os.path.exists(path):
        # Path no longer exists. It must have been deleted in another commit.
        continue

      try:
        _ = osv.parse_vulnerability(
            path, key_path=source_repo.key_path, strict=self._strict_validation)
      except osv.sources.KeyPathError:
        # Key path doesn't exist in the vulnerability.
        # No need to log a full error, as this is expected result.
        logging.info('Entry does not have an OSV entry: %s', changed_entry)
        continue
      except Exception as e:
        logging.error('Failed to parse %s: %s', changed_entry, str(e))
        # Don't include error stack trace as that might leak sensitive info
        import_failure_logs.append('Failed to parse vulnerability "' + path +
                                   '"')
        continue

      logging.info('Re-analysis triggered for %s', changed_entry)
      original_sha256 = osv.sha256(path)
      self._request_analysis_external(source_repo, original_sha256,
                                      changed_entry)

    replace_importer_log(storage.Client(), source_repo.name,
                         self._public_log_bucket, import_failure_logs)
    source_repo.last_synced_hash = str(repo.head.target)
    source_repo.put()

    logging.info('Finished processing git: %s', source_repo.name)

  def _process_updates_bucket(self, source_repo: osv.SourceRepository):
    """Process updates from bucket."""
    # TODO(ochang): Use Pub/Sub change notifications for more efficient
    # processing.
    logging.info("Begin processing bucket for updates: %s", source_repo.name)

    # Record import time at the start to avoid race conditions
    # where a new record is added to the bucket while we are processing.
    import_time_now = utcnow()

    if not source_repo.last_update_date:
      source_repo.last_update_date = datetime.datetime.min

    ignore_last_import_time = source_repo.ignore_last_import_time
    if ignore_last_import_time:
      source_repo.ignore_last_import_time = False
      source_repo.put()

    # First retrieve a list of files to parallel download
    storage_client = storage.Client()
    utc_last_update_date = source_repo.last_update_date.replace(
        tzinfo=datetime.timezone.utc)

    # Convert to list to retrieve all information into memory
    # This makes its use in the concurrent map later faster
    listed_blobs = list(
        storage_client.list_blobs(
            source_repo.bucket, prefix=source_repo.directory_path))

    import_failure_logs = []

    # TODO(andrewpollock): externalise like _vuln_ids_from_gcs_blob()
    def convert_blob_to_vuln(blob: storage.Blob) -> Optional[Tuple[str, str]]:
      """Download and parse GCS blob into [blob_hash, blob.name]"""
      if not _is_vulnerability_file(source_repo, blob.name):
        return None
      if not ignore_last_import_time and \
         not blob.time_created > utc_last_update_date:
        return None

      logging.info('Bucket entry triggered for %s/%s', source_repo.bucket,
                   blob.name)
      # Use the _client_store thread local variable
      # set in the thread pool initializer
      # Download in a blob generation agnostic way to cope with the file
      # changing between when it was listed and now.
      blob_bytes = storage.Blob(
          blob.name, blob.bucket,
          generation=None).download_as_bytes(_client_store.storage_client)
      if ignore_last_import_time:
        blob_hash = osv.sha256_bytes(blob_bytes)
        if self._strict_validation:
          try:
            _ = osv.parse_vulnerabilities_from_data(
                blob_bytes,
                os.path.splitext(blob.name)[1],
                strict=self._strict_validation)
          except Exception as e:
            logging.error('Failed to parse vulnerability %s: %s', blob.name, e)
            import_failure_logs.append('Failed to parse vulnerability "' +
                                       blob.name + '"')
            return None
        return blob_hash, blob.name

      with _client_store.ndb_client.context():
        try:
          vulns = osv.parse_vulnerabilities_from_data(
              blob_bytes,
              os.path.splitext(blob.name)[1],
              strict=self._strict_validation)
          for vuln in vulns:
            bug = osv.Bug.get_by_id(vuln.id)
            # Check if the bug has been modified since last import
            if bug is None or \
                    bug.import_last_modified != vuln.modified.ToDatetime():
              blob_hash = osv.sha256_bytes(blob_bytes)
              return blob_hash, blob.name

          return None
        except Exception as e:
          logging.error('Failed to parse vulnerability %s: %s', blob.name, e)
          # Don't include error stack trace as that might leak sensitive info
          # List.append() is atomic and threadsafe.
          import_failure_logs.append('Failed to parse vulnerability "' +
                                     blob.name + '"')
          return None

    # Setup storage client
    def thread_init():
      _client_store.storage_client = storage.Client()
      _client_store.ndb_client = ndb.Client()

    # TODO(andrewpollock): switch to using c.f.submit() like in
    # _process_deletions_bucket()
    with concurrent.futures.ThreadPoolExecutor(
        _BUCKET_THREAD_COUNT, initializer=thread_init) as executor:
      converted_vulns = executor.map(convert_blob_to_vuln, listed_blobs)
      for cv in converted_vulns:
        if cv:
          logging.info('Requesting analysis of bucket entry: %s/%s',
                       source_repo.bucket, cv[1])
          self._request_analysis_external(source_repo, cv[0], cv[1])

    replace_importer_log(storage_client, source_repo.name,
                         self._public_log_bucket, import_failure_logs)

    source_repo.last_update_date = import_time_now
    source_repo.put()

    logging.info('Finished processing bucket: %s', source_repo.name)

  def _process_deletions_bucket(self,
                                source_repo: osv.SourceRepository,
                                threshold: float = 10.0):
    """Process deletions from a GCS bucket source.

    This validates the continued existence of every Bug in Datastore (for the
    given source) against every bug currently in that source's GCS bucket,
    calculating the delta. The bugs determined to have been
    deleted from GCS are then flagged for treatment by the worker.

    If the delta is too large, something undesirable has been assumed to have
    happened and further processing is aborted.

    Args:
      source_repo: the osv.SourceRepository being operated on
      threshold: the percentage delta considered safe to delete
    """

    logging.info('Begin processing bucket for deletions: %s', source_repo.name)

    # Get all the existing non-withdrawn Bug IDs for
    # source_repo.name in Datastore
    query = osv.Bug.query()
    query = query.filter(osv.Bug.source == source_repo.name)
    result = list(query.fetch(keys_only=False))
    result.sort(key=lambda r: r.id())
    VulnAndSource = namedtuple('VulnAndSource', ['id', 'path'])
    vuln_ids_for_source = [
        VulnAndSource(id=r.id(), path=r.source_id.split(':')[1])
        for r in result
        if not r.withdrawn
    ]
    logging.info('Counted %d Bugs for %s in Datastore',
                 len(vuln_ids_for_source), source_repo.name)

    storage_client = storage.Client()
    # Get all of the existing records in the GCS bucket
    # (to get their IDs for checking against Datastore)
    logging.info(
        'Listing blobs in gs://%s',
        os.path.join(source_repo.bucket,
                     ('' if source_repo.directory_path is None else
                      source_repo.directory_path)))
    listed_blobs = list(
        storage_client.list_blobs(
            source_repo.bucket, prefix=source_repo.directory_path))

    import_failure_logs = []

    # Get the vulnerability ID from every GCS object that parses as an OSV
    # record. Do this in parallel for a degree of expedience.
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_BUCKET_THREAD_COUNT) as executor:
      logging.info('Parallel-parsing %d blobs in %s', len(listed_blobs),
                   source_repo.name)
      future_to_blob = {
          executor.submit(self._vuln_ids_from_gcs_blob, storage.Client(),
                          source_repo, blob):
              blob for blob in listed_blobs
      }
      vuln_ids_in_gcs = []
      logging.info('Processing %d parallel-parsed blobs in %s',
                   len(future_to_blob), source_repo.name)
      for future in concurrent.futures.as_completed(future_to_blob):
        blob = future_to_blob[future]
        try:
          if future.result():
            vuln_ids_in_gcs.extend(
                [vuln_id for vuln_id in future.result() if vuln_id])
        except Exception as e:
          # Don't include error stack trace as that might leak sensitive info
          logging.error('Failed to parse vulnerability %s: %s', blob.name, e)
          # List.append() is atomic and threadsafe.
          import_failure_logs.append(
              'Failed to parse vulnerability (when considering for deletion)"' +
              blob.name + '"')
    logging.info('Counted %d parsed vulnerabilities (from %d blobs) for %s',
                 len(vuln_ids_in_gcs), len(listed_blobs), source_repo.name)

    # diff what's in Datastore with what was seen in GCS.
    vulns_to_delete = [
        v for v in vuln_ids_for_source if v.id not in vuln_ids_in_gcs
    ]

    logging.info('%d Bugs in Datastore considered deleted from GCS for %s',
                 len(vulns_to_delete), source_repo.name)

    if len(vulns_to_delete) == 0:
      replace_importer_log(storage_client, source_repo.name,
                           self._public_log_bucket, import_failure_logs)
      return

    # sanity check: deleting a lot/all of the records for source in Datastore is
    # probably worth flagging for review.
    if (len(vulns_to_delete) / len(vuln_ids_for_source) * 100) >= threshold:
      logging.error(
          'Cowardly refusing to delete %d missing records from '
          'GCS for: %s', len(vulns_to_delete), source_repo.name)
      return

    # Request deletion.
    for v in vulns_to_delete:
      logging.info('Requesting deletion of bucket entry: %s/%s for %s',
                   source_repo.bucket, v.path, v.id)
      self._request_analysis_external(
          source_repo, original_sha256='', path=v.path, deleted=True)

    replace_importer_log(storage_client, source_repo.name,
                         self._public_log_bucket, import_failure_logs)

  def _process_updates_rest(self, source_repo: osv.SourceRepository):
    """Process updates from REST API."""
    logging.info('Begin processing REST: %s', source_repo.name)

    ignore_last_import_time = (
        source_repo.ignore_last_import_time or not source_repo.last_update_date)
    if ignore_last_import_time:
      source_repo.ignore_last_import_time = False
      source_repo.put()
    import_time_now = utcnow()
    request = requests.head(source_repo.rest_api_url, timeout=_TIMEOUT_SECONDS)
    if request.status_code != 200:
      logging.error('Failed to fetch REST API: %s', request.status_code)
      return

    if 'Last-Modified' in request.headers:
      last_modified = datetime.datetime.strptime(
          request.headers['Last-Modified'], _HTTP_LAST_MODIFIED_FORMAT)
      # Check whether endpoint has been modified since last update
      if not ignore_last_import_time and (last_modified
                                          < source_repo.last_update_date):
        logging.info('No changes since last update.')
        return

    request = requests.get(source_repo.rest_api_url, timeout=_TIMEOUT_SECONDS)
    # Parse vulns into Vulnerability objects from the REST API request.
    vulns = osv.parse_vulnerabilities_from_data(
        request.text, source_repo.extension, strict=self._strict_validation)
    # Create tasks for changed files.
    for vuln in vulns:
      import_failure_logs = []
      if not ignore_last_import_time and vuln.modified.ToDatetime(
      ) < source_repo.last_update_date:
        continue
      try:
        # TODO(jesslowe): Use a ThreadPoolExecutor to parallelize this
        single_vuln = requests.get(
            source_repo.link + vuln.id + source_repo.extension,
            timeout=_TIMEOUT_SECONDS)
        # Validate the individual request
        _ = osv.parse_vulnerability_from_dict(single_vuln.json(),
                                              source_repo.key_path,
                                              self._strict_validation)
        self._request_analysis_external(
            source_repo, osv.sha256_bytes(single_vuln.text.encode()),
            vuln.id + source_repo.extension)
      except osv.sources.KeyPathError:
        # Key path doesn't exist in the vulnerability.
        # No need to log a full error, as this is expected result.
        logging.info('Entry does not have an OSV entry: %s', vuln.id)
        continue
      except Exception:
        logging.error('Failed to parse %s', vuln.id)
        import_failure_logs.append('Failed to parse vulnerability "' + vuln.id +
                                   '"')
        continue

    replace_importer_log(storage.Client(), source_repo.name,
                         self._public_log_bucket, import_failure_logs)

    source_repo.last_update_date = import_time_now
    source_repo.put()

    logging.info('Finished processing REST: %s', source_repo.name)

  def _process_deletions_rest(self, source_repo: osv.SourceRepository):
    """Process deletions from a REST bucket source."""
    raise NotImplementedError

  def validate_source_repo(self, source_repo: osv.SourceRepository):
    """Validate the source_repo for correctness."""
    if source_repo.link and source_repo.link[-1] != '/':
      raise ValueError('Source repository link must end with /')

  def process_updates(self, source_repo: osv.SourceRepository):
    """Process source record changes and updates."""
    if source_repo.type == osv.SourceRepositoryType.GIT:
      self._process_updates_git(source_repo)
      return

    if source_repo.type == osv.SourceRepositoryType.BUCKET:
      self._process_updates_bucket(source_repo)
      return

    if source_repo.type == osv.SourceRepositoryType.REST_ENDPOINT:
      self._process_updates_rest(source_repo)
      return

    logging.error('Invalid repo type: %s - %d', source_repo.name,
                  source_repo.type)

  def process_deletions(self, source_repo: osv.SourceRepository):
    """Process source record deletions by withdrawing them."""
    if source_repo.type == osv.SourceRepositoryType.GIT:
      # TODO: To be implemented.
      # NOTE: this may require reintroducing special node GKE node treatment
      # see discussion on https://github.com/google/osv.dev/pull/2133
      return

    if source_repo.type == osv.SourceRepositoryType.BUCKET:
      self._process_deletions_bucket(source_repo,
                                     self._deletion_safety_threshold_pct)
      return

    if source_repo.type == osv.SourceRepositoryType.REST_ENDPOINT:
      # TODO: To be implemented.
      return

    logging.error('Invalid repo type: %s - %d', source_repo.name,
                  source_repo.type)

  def process_oss_fuzz(self, oss_fuzz_source):
    """Process OSS-Fuzz source data."""
    # Export OSS-Fuzz Vulnerability data into source repository.
    # OSS-Fuzz data is first imported via a special Pub/Sub pipeline into OSV.
    # This data needs to be dumped into a publicly accessible/editable place for
    # manual/human editing if required.
    #
    # This then becomes the source of truth where any edits are imported back
    # into OSV.
    repo = self.checkout(oss_fuzz_source)
    self.schedule_regular_updates(repo, oss_fuzz_source)
    self.import_new_oss_fuzz_entries(repo, oss_fuzz_source)
    self.export_oss_fuzz_to_bucket()

  def export_oss_fuzz_to_bucket(self):
    """Export OSS-Fuzz vulns to bucket."""
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(self._oss_fuzz_export_bucket)

    def export_oss_fuzz(vulnerability, testcase_id, issue_id):
      """Export a single vulnerability."""
      try:
        blob = bucket.blob(f'testcase/{testcase_id}.json')
        data = json.dumps(osv.vulnerability_to_dict(vulnerability))
        blob.upload_from_string(data)

        if not issue_id:
          return

        blob = bucket.blob(f'issue/{issue_id}.json')
        blob.upload_from_string(data)
      except Exception as e:
        logging.error('Failed to export: %s', e)

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=_EXPORT_WORKERS) as executor:
      for bug in osv.Bug.query(osv.Bug.ecosystem == 'OSS-Fuzz'):
        if not bug.public:
          continue

        _, source_id = osv.parse_source_id(bug.source_id)
        executor.submit(export_oss_fuzz, bug.to_vulnerability(), source_id,
                        bug.issue_id)


def main():
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
