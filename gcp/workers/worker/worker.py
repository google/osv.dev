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
"""OSV Worker."""
import argparse
import datetime
import json
import logging
import os
import pygit2
import redis
import requests
import resource
import shutil
import subprocess
import sys
import threading
import time

import google.cloud.exceptions
from google.cloud import ndb
from google.cloud import pubsub_v1
from google.cloud import storage
from google.cloud.storage import retry
from google.protobuf import json_format, timestamp_pb2

sys.path.append(os.path.dirname(os.path.realpath(__file__)))
import osv
import osv.cache
import osv.ecosystems
import osv.gcs
import osv.logs
from osv import vulnerability_pb2, purl_helpers
import oss_fuzz

from vanir import vulnerability_manager

DEFAULT_WORK_DIR = '/work'
OSS_FUZZ_GIT_URL = 'https://github.com/google/oss-fuzz.git'
TASK_SUBSCRIPTION = 'tasks'
MAX_LEASE_DURATION = 6 * 60 * 60  # 4 hours.
_TIMEOUT_SECONDS = 60

_ECOSYSTEM_PUSH_TOPICS = {
    'PyPI': 'pypi-bridge',
}

_state = threading.local()
_state.source_id = None
_state.bug_id = None


class RedisCache(osv.cache.Cache):
  """Redis cache implementation."""

  redis_instance: redis.client.Redis

  def __init__(self, host, port):
    self.redis_instance = redis.Redis(host, port)

  def get(self, key):
    try:
      return json.loads(self.redis_instance.get(json.dumps(key)))
    except Exception:
      # TODO(ochang): Remove this after old cache entries are flushed.
      return None

  def set(self, key, value, ttl):
    return self.redis_instance.set(json.dumps(key), json.dumps(value), ex=ttl)


class UpdateConflictError(Exception):
  """Update conflict exception."""


class _ContextFilter(logging.Filter):
  """Context filter to add extra GCP logging information."""

  def filter(self, record):
    """Add extra fields to the log record."""
    json_fields = getattr(record, 'json_fields', {})

    if getattr(_state, 'source_id', None):
      json_fields['source_id'] = _state.source_id

    if getattr(_state, 'bug_id', None):
      json_fields['bug_id'] = _state.bug_id

    json_fields['thread'] = record.thread
    record.json_fields = json_fields
    return True


def _setup_logging_extra_info():
  """Set up extra GCP logging information."""
  logging.getLogger().addFilter(_ContextFilter())


class _PubSubLeaserThread(threading.Thread):
  """Thread that continuously renews the lease for a message."""

  EXTENSION_TIME_SECONDS = 10 * 60  # 10 minutes.

  def __init__(self, subscriber_client, subscription, ack_id, done_event,
               max_lease_seconds):
    super().__init__()
    self.daemon = True
    self._subscriber = subscriber_client
    self._subscription = subscription
    self._ack_id = ack_id
    self._done_event = done_event
    self._max_lease_seconds = max_lease_seconds

  def run(self):
    """Run the leaser thread."""
    latest_end_time = time.time() + self._max_lease_seconds

    while True:
      try:
        time_left = latest_end_time - time.time()
        if time_left <= 0:
          logging.warning(
              'Lease reached maximum lease time of %d seconds, '
              'stopping renewal.', self._max_lease_seconds)
          break

        extension_seconds = int(min(self.EXTENSION_TIME_SECONDS, time_left))

        logging.info('Renewing lease for task by %d seconds.',
                     extension_seconds)
        self._subscriber.modify_ack_deadline(
            subscription=self._subscription,
            ack_ids=[self._ack_id],
            ack_deadline_seconds=extension_seconds)

        # Schedule renewals earlier than the extension to avoid race conditions
        # and performing the next extension too late.
        wait_seconds = min(time_left, self.EXTENSION_TIME_SECONDS // 2)

        # Wait until the next scheduled renewal, or if the task is complete.
        if self._done_event.wait(wait_seconds):
          logging.info('Task complete, stopping renewal.')
          break
      except Exception:
        logging.exception('Leaser thread failed: ')


def clean_artifacts(oss_fuzz_dir):
  """Clean build artifact from previous runs."""
  build_dir = os.path.join(oss_fuzz_dir, 'build')
  if os.path.exists(build_dir):
    shutil.rmtree(build_dir, ignore_errors=True)


def get_source_id(message):
  """Get message ID."""
  source_id = message.attributes['source_id']
  if source_id:
    return source_id

  testcase_id = message.attributes['testcase_id']
  if testcase_id:
    return oss_fuzz.SOURCE_PREFIX + testcase_id

  return None


def add_fix_information(vulnerability, fix_result):
  """Add fix information to a vulnerability."""
  database_specific = {}
  fix_commit = fix_result.commit
  if ':' in fix_result.commit:
    database_specific['fixed_range'] = fix_result.commit
    fix_commit = fix_result.commit.split(':')[1]

  has_changes = False

  for affected_package in vulnerability.affected:
    added_fix = False

    # Count unique repo URLs.
    repos = set()
    for affected_range in affected_package.ranges:
      if affected_range.type == vulnerability_pb2.Range.GIT:
        repos.add(affected_range.repo)

    for affected_range in affected_package.ranges:
      if affected_range.type != vulnerability_pb2.Range.GIT:
        continue

      # If this range does not include the fixed commit, add it.
      # Do this if:
      #   - There is only one repo URL in the entire vulnerability, or
      #   - The repo URL matches the FixResult repo URL.
      if ((fix_result.repo_url == affected_range.repo or len(repos) == 1) and
          not any(event.fixed == fix_commit
                  for event in affected_range.events)):
        added_fix = True
        has_changes = True
        affected_range.events.add(fixed=fix_commit)
        # Clear existing versions to re-compute them from scratch.
        del affected_package.versions[:]

    if added_fix:
      affected_package.database_specific.update(database_specific)

  return has_changes


# TODO(ochang): Remove this function once GHSA's encoding is fixed.
def fix_invalid_ghsa(vulnerability):
  """Attempt to fix an invalid GHSA entry.

  Args:
    vulnerability: a vulnerability object.

  Returns:
    whether the GHSA entry is valid.
  """
  packages = {}
  for affected in vulnerability.affected:
    details = packages.setdefault(
        (affected.package.ecosystem, affected.package.name), {
            'has_single_introduced': False,
            'has_fixed': False
        })

    has_bad_equals_encoding = False
    for affected_range in affected.ranges:
      if len(
          affected_range.events) == 1 and affected_range.events[0].introduced:
        details['has_single_introduced'] = True
        if (affected.versions and
            affected.versions[0] == affected_range.events[0].introduced):
          # https://github.com/github/advisory-database/issues/59.
          has_bad_equals_encoding = True

      for event in affected_range.events:
        if event.fixed:
          details['has_fixed'] = True

    if has_bad_equals_encoding:
      if len(affected.ranges) == 1:
        # Try to fix this by removing the range.
        del affected.ranges[:]
        logging.info('Removing bad range from %s', vulnerability.id)
      else:
        # Unable to fix this if there are multiple ranges.
        return False

  for details in packages.values():
    # Another case of a bad encoding: Having ranges with a single "introduced"
    # event, when there are actually "fix" events encoded in another range for
    # the same package.
    if details['has_single_introduced'] and details['has_fixed']:
      return False

  return True


def maybe_normalize_package_names(
    vulnerability: vulnerability_pb2.Vulnerability
) -> vulnerability_pb2.Vulnerability:
  """Normalize package names as necessary."""
  for affected in vulnerability.affected:
    if not affected.package.ecosystem:
      continue
    affected.package.name = osv.ecosystems.maybe_normalize_package_names(
        affected.package.name, affected.package.ecosystem)

  return vulnerability


def filter_unknown_ecosystems(vulnerability):
  """Remove unknown ecosystems from vulnerability."""
  filtered = []
  for affected in vulnerability.affected:
    # CVE-converted OSV records have no package information.
    if not affected.HasField('package'):
      filtered.append(affected)
    elif osv.ecosystems.is_known(affected.package.ecosystem):
      filtered.append(affected)
    else:
      logging.error('%s contains unknown ecosystem "%s"', vulnerability.id,
                    affected.package.ecosystem)
  del vulnerability.affected[:]
  vulnerability.affected.extend(filtered)


class TaskRunner:
  """Task runner."""

  def __init__(self, ndb_client, oss_fuzz_dir, work_dir, ssh_key_public_path,
               ssh_key_private_path):
    self._ndb_client = ndb_client
    self._oss_fuzz_dir = oss_fuzz_dir
    self._work_dir = work_dir
    self._sources_dir = os.path.join(self._work_dir, 'sources')
    self._ssh_key_public_path = ssh_key_public_path
    self._ssh_key_private_path = ssh_key_private_path
    os.makedirs(self._sources_dir, exist_ok=True)
    logging.info('Created task runner')

  def _git_callbacks(self, source_repo):
    """Get git auth callbacks."""
    return osv.GitRemoteCallback(source_repo.repo_username,
                                 self._ssh_key_public_path,
                                 self._ssh_key_private_path)

  def _source_update(self, message):
    """Source update."""
    source = message.attributes['source']
    path = message.attributes['path']
    original_sha256 = message.attributes['original_sha256']
    deleted = message.attributes['deleted'] == 'true'
    skip_hash_check = message.attributes.get('skip_hash_check') == 'true'

    source_repo = osv.get_source_repository(source)
    if source_repo is None:
      raise ValueError('Failed to get source repository %s' % source)

    if source_repo.type == osv.SourceRepositoryType.GIT:
      repo = osv.ensure_updated_checkout(
          source_repo.repo_url,
          os.path.join(self._sources_dir, source),
          git_callbacks=self._git_callbacks(source_repo),
          branch=source_repo.repo_branch)

      vuln_path = os.path.join(osv.repo_path(repo), path)
      if not os.path.exists(vuln_path):
        logging.info('%s was deleted.', vuln_path)
        if deleted or skip_hash_check:
          self._handle_deleted(path)

        return

      if deleted:
        logging.info('Deletion request but source still exists, aborting.')
        return

      try:
        vulnerabilities = osv.parse_vulnerabilities(
            vuln_path, key_path=source_repo.key_path)
      except Exception:
        logging.exception('Failed to parse vulnerability %s:', vuln_path)
        return

      current_sha256 = osv.sha256(vuln_path)
    elif source_repo.type == osv.SourceRepositoryType.BUCKET:
      if deleted:
        self._handle_deleted(path)
        return
      storage_client = storage.Client()
      bucket = storage_client.bucket(source_repo.bucket)
      try:
        blob = bucket.blob(path).download_as_bytes(retry=retry.DEFAULT_RETRY)
      except google.cloud.exceptions.NotFound:
        logging.exception('Bucket path %s does not exist.', path)
        if skip_hash_check:
          self._handle_deleted(path)
        return

      current_sha256 = osv.sha256_bytes(blob)
      try:
        vulnerabilities = osv.parse_vulnerabilities_from_data(
            blob,
            extension=os.path.splitext(path)[1],
            key_path=source_repo.key_path)
      except Exception:
        logging.exception('Failed to parse vulnerability %s', path)
        return

      repo = None
    elif source_repo.type == osv.SourceRepositoryType.REST_ENDPOINT:
      if deleted:
        self._handle_deleted(path)
        return
      vulnerabilities = []
      request = requests.get(source_repo.link + path, timeout=_TIMEOUT_SECONDS)
      if request.status_code != 200:
        logging.error('Failed to fetch REST API: %s', request.status_code)
        if request.status_code == 404 and skip_hash_check:
          self._handle_deleted(path)
        return
      vuln = request.json()
      try:
        vulnerabilities.append(osv.parse_vulnerability_from_dict(vuln))
      except Exception as e:
        logging.exception('Failed to parse %s:%s', vuln['id'], e)
      current_sha256 = osv.sha256_bytes(request.text.encode())
      repo = None

    else:
      raise RuntimeError('Unsupported SourceRepository type.')

    if not skip_hash_check and current_sha256 != original_sha256:
      logging.warning(
          'sha256sum of %s no longer matches (expected=%s vs current=%s).',
          path, original_sha256, current_sha256)
      return

    if len(vulnerabilities) > 1:
      # While the code allows for having multiple vulnerabilities in a file,
      # it's not really documented anywhere, and no one seems to be doing this.
      # I (michaelkedar) think we should stop supporting this, so adding this
      # log here to verify if it's okay to remove.
      logging.error(
          'file has multiple vulnerabilities',
          extra={'json_fields': {
              'source': source,
              'path': path,
          }})

    for vulnerability in vulnerabilities:
      self._do_update(source_repo, repo, vulnerability, path, original_sha256)

  def _handle_deleted(self, vuln_path: str):
    """Handle existing vulns that have been subsequently deleted at their
    source.

    Args:
      vuln_path: Path to vulnerability.

    This marks the Vulnerability as withdrawn.
    """
    vuln_id = os.path.splitext(os.path.basename(vuln_path))[0]
    vuln_and_gen = osv.gcs.get_by_id_with_generation(vuln_id)
    gcs_gen = None
    proto_vuln = None

    def xact():
      nonlocal gcs_gen
      nonlocal proto_vuln
      ds_vuln: osv.Vulnerability = osv.Vulnerability.get_by_id(vuln_id)
      if not ds_vuln:
        logging.error('Failed to find Vulnerability with ID %s', vuln_id)
        return

      _, _, ds_path = ds_vuln.source_id.partition(':')

      if ds_path != vuln_path:
        logging.error('Request path %s does not match %s, aborting.', vuln_path,
                      ds_path)
        return

      logging.info('Marking %s as withdrawn.', vuln_id)
      if not vuln_and_gen:
        logging.error('Failed to find Vulnerability with ID %s in GCS', vuln_id)
        # contruct an empty withdrawn vuln
        proto_vuln = vulnerability_pb2.Vulnerability(id=vuln_id)
      else:
        proto_vuln, gcs_gen = vuln_and_gen

      if not proto_vuln.HasField('withdrawn'):
        # in case this was already withdrawn for some reason
        proto_vuln.withdrawn.FromDatetime(datetime.datetime.now(datetime.UTC))
      if (not proto_vuln.HasField('modified') or
          proto_vuln.withdrawn.ToDatetime(
              datetime.UTC) > proto_vuln.modified.ToDatetime(datetime.UTC)):
        proto_vuln.modified.CopyFrom(proto_vuln.withdrawn)
      ds_vuln.is_withdrawn = True
      ds_vuln.modified = proto_vuln.modified.ToDatetime(datetime.UTC)
      osv.models.put_entities(ds_vuln, proto_vuln)

    try:
      ndb.transaction(xact)
    except (google.api_core.exceptions.Cancelled, ndb.exceptions.Error) as e:
      e.add_note(f'Happened processing {vuln_id}')
      logging.exception('Unexpected exception while writing %s to Datastore',
                        vuln_id)
      raise
    if not proto_vuln:
      return
    try:
      osv.gcs.upload_vulnerability(proto_vuln, gcs_gen)
    except Exception:
      # Writing to bucket failed for some reason.
      # Send a pub/sub message to retry.
      logging.error('Writing to bucket failed for %s', vuln_id)
      data = proto_vuln.SerializeToString(deterministic=True)
      osv.pubsub.publish_failure(data, type='gcs_retry')

  def _push_new_ranges_and_versions(self, source_repo, repo, vulnerability,
                                    output_path, original_sha256):
    """Pushes new ranges and versions."""
    osv.write_vulnerability(
        vulnerability, output_path, key_path=source_repo.key_path)
    repo.index.add_all()
    return osv.push_source_changes(
        repo,
        f'Update {vulnerability.id}',
        self._git_callbacks(source_repo),
        expected_hashes={
            output_path: original_sha256,
        })

  def _analyze_vulnerability(self, source_repo: osv.SourceRepository,
                             repo: pygit2.Repository | None,
                             vulnerability: vulnerability_pb2.Vulnerability,
                             path: str,
                             original_sha256: str) -> osv.AnalyzeResult:
    """Analyze vulnerability and push new changes."""
    result = osv.analyze(
        vulnerability,
        checkout_path=os.path.join(self._work_dir, 'checkout'),
        analyze_git=not source_repo.ignore_git,
        detect_cherrypicks=source_repo.detect_cherrypicks,
        versions_from_repo=source_repo.versions_from_repo,
        consider_all_branches=source_repo.consider_all_branches)

    if not result.has_changes:
      return result

    if not source_repo.editable:
      return result
    # NB: Only OSS-Fuzz is editable - all other sources are read-only.
    # This should not be reachable by this worker.
    logging.error('Source %s flagged as editable', source_repo.name)
    output_path = os.path.join(osv.repo_path(repo), path)
    if self._push_new_ranges_and_versions(source_repo, repo, vulnerability,
                                          output_path, original_sha256):
      logging.info('Updated range/versions for vulnerability %s.',
                   vulnerability.id)
      return result

    logging.warning('Discarding changes for %s due to conflicts.',
                    vulnerability.id)
    raise UpdateConflictError

  def _generate_vanir_signatures(
      self, vulnerability: vulnerability_pb2.Vulnerability
  ) -> vulnerability_pb2.Vulnerability:
    """Generates Vanir signatures for a vulnerability."""
    if not any(r.type == vulnerability_pb2.Range.GIT
               for affected in vulnerability.affected
               for r in affected.ranges):
      logging.info(
          'Skipping Vanir signature generation for %s as it has no '
          'GIT affected ranges.', vulnerability.id)
      return vulnerability
    if any(affected.package.name == "Kernel" and
           affected.package.ecosystem == "Linux"
           for affected in vulnerability.affected):
      logging.info(
          'Skipping Vanir signature generation for %s as it is a '
          'Kernel vulnerability.', vulnerability.id)
      return vulnerability

    logging.info('Generating Vanir signatures for %s', vulnerability.id)
    try:
      vuln_manager = vulnerability_manager.generate_from_json_string(
          content=json.dumps([
              json_format.MessageToDict(
                  vulnerability, preserving_proto_field_name=True)
          ]),)
      vuln_manager.generate_signatures()

      if not vuln_manager.vulnerabilities:
        logging.warning('Vanir signature generation resulted in no '
                        'vulnerabilities.')
        return vulnerability

      return vuln_manager.vulnerabilities[0].to_proto()
    except Exception:
      logging.exception('Failed to generate Vanir signatures for %s',
                        vulnerability.id)
      return vulnerability

  def _do_update(self, source_repo: osv.SourceRepository,
                 repo: pygit2.Repository | None,
                 vulnerability: vulnerability_pb2.Vulnerability,
                 relative_path: str, original_sha256: str):
    """Process updates on a vulnerability."""
    _state.bug_id = vulnerability.id
    logging.info('Processing update for vulnerability %s', vulnerability.id)
    vulnerability = maybe_normalize_package_names(vulnerability)
    if source_repo.name == 'ghsa' and not fix_invalid_ghsa(vulnerability):
      logging.warning('%s has an encoding error, skipping.', vulnerability.id)
      return

    filter_unknown_ecosystems(vulnerability)

    # Keep a copy of the original modified date from the source file.
    orig_modified_date = vulnerability.modified.ToDatetime(datetime.UTC)

    # Fully enrich the vulnerability object in memory.
    vulnerability = self._generate_vanir_signatures(vulnerability)
    try:
      result = self._analyze_vulnerability(source_repo, repo, vulnerability,
                                           relative_path, original_sha256)
    except UpdateConflictError:
      # Discard changes due to conflict.
      return

    vuln_and_gen = osv.gcs.get_by_id_with_generation(vulnerability.id)
    gcs_gen = None

    def xact():
      # Fetch the current state from Datastore.
      nonlocal gcs_gen
      ds_vuln = osv.Vulnerability.get_by_id(vulnerability.id)
      is_new_bug = ds_vuln is None

      old_published = None

      # Update the schema version
      # TODO(michaelkedar): osv.SCHEMA_VERSION is not kept up to date with
      # the osv-schema submodule
      vulnerability.schema_version = osv.SCHEMA_VERSION
      # Add PURLs and source if they are missing.
      source_link = None
      if source_repo and source_repo.link:
        source_link = source_repo.link + relative_path
      for affected in vulnerability.affected:
        if not affected.package.purl:
          if purl := purl_helpers.package_to_purl(
              osv.ecosystems.normalize(affected.package.ecosystem),
              affected.package.name):
            affected.package.purl = purl
        if source_link:
          affected.database_specific.update({'source': source_link})

      has_changed = False
      if is_new_bug:
        has_changed = True
        ds_vuln = osv.Vulnerability(
            id=vulnerability.id,
            source_id=f'{source_repo.name}:{relative_path}',
        )
      else:
        # Compare the newly enriched vulnerability with the stored one.
        # Create a 'pure' vulnerability object from the existing vuln for
        # comparison, excluding external data that would cause false positives.
        if vuln_and_gen is None:
          logging.warning('Vulnerability %s found in Datastore but not in GCS.',
                          vulnerability.id)
          # We need to write the vuln in this case
          has_changed = True
        else:
          old_vulnerability, gcs_gen = vuln_and_gen
          if old_vulnerability.HasField('published'):
            old_published = timestamp_pb2.Timestamp()
            old_published.CopyFrom(old_vulnerability.published)
          new_vulnerability = vulnerability_pb2.Vulnerability()
          new_vulnerability.CopyFrom(vulnerability)

          # Clear modified/published timestamps for a clean comparison.
          old_vulnerability.modified.Clear()
          new_vulnerability.modified.Clear()
          old_vulnerability.published.Clear()
          new_vulnerability.published.Clear()
          # Clear aliases and upstream, as they are computed separately.
          old_vulnerability.aliases.clear()
          new_vulnerability.aliases.clear()
          old_vulnerability.upstream.clear()
          new_vulnerability.upstream.clear()
          old_vulnerability.related.clear()
          new_vulnerability.related.clear()

          has_changed = old_vulnerability != new_vulnerability

      ds_vuln.is_withdrawn = vulnerability.HasField('withdrawn')
      ds_vuln.modified_raw = orig_modified_date
      ds_vuln.alias_raw = list(vulnerability.aliases)
      ds_vuln.related_raw = list(vulnerability.related)
      ds_vuln.upstream_raw = list(vulnerability.upstream)
      # Update the bug entity based on the comparison.
      if has_changed:
        ds_vuln.modified = osv.utcnow()
      else:
        # If no meaningful change, ensure last_modified reflects the source
        # file's modified date, as only metadata might have changed.
        ds_vuln.modified = orig_modified_date

      # Overwrite aliases / upstream from computation
      alias_group = osv.AliasGroup.query(
          osv.AliasGroup.bug_ids == vulnerability.id).get()
      if alias_group:
        aliases = sorted(set(alias_group.bug_ids) - {vulnerability.id})
        vulnerability.aliases[:] = aliases
        ds_vuln.modified = max(alias_group.last_modified, ds_vuln.modified)
      upstream_group = osv.UpstreamGroup.query(
          osv.UpstreamGroup.db_id == vulnerability.id).get()
      if upstream_group:
        vulnerability.upstream[:] = sorted(upstream_group.upstream_ids)
        ds_vuln.modified = max(upstream_group.last_modified, ds_vuln.modified)
      related_group = osv.RelatedGroup.get_by_id(vulnerability.id)
      if related_group:
        vulnerability.related[:] = sorted(related_group.related_ids)
        ds_vuln.modified = max(related_group.modified, ds_vuln.modified)
      # Make sure modified date is >= withdrawn date
      if ds_vuln.is_withdrawn and vulnerability.withdrawn.ToDatetime(
          datetime.UTC) > ds_vuln.modified:
        ds_vuln.modified = vulnerability.withdrawn.ToDatetime(datetime.UTC)

      vulnerability.modified.FromDatetime(ds_vuln.modified)

      # Make sure vuln has a published date
      if not vulnerability.HasField('published'):
        if old_published:
          vulnerability.published.CopyFrom(old_published)
        else:
          vulnerability.published.CopyFrom(vulnerability.modified)

      osv.models.put_entities(ds_vuln, vulnerability)
      osv.update_affected_commits(vulnerability.id, result.commits, True)

    try:
      ndb.transaction(xact)
    except (google.api_core.exceptions.Cancelled, ndb.exceptions.Error) as e:
      e.add_note(f'Happened processing {vulnerability.id}')
      logging.exception('Unexpected exception while writing %s to Datastore',
                        vulnerability.id)
      raise
    try:
      osv.gcs.upload_vulnerability(vulnerability, gcs_gen)
    except Exception:
      # Writing to bucket failed for some reason.
      # Send a pub/sub message to retry.
      logging.error('Writing to bucket failed for %s', vulnerability.id)
      data = vulnerability.SerializeToString(deterministic=True)
      osv.pubsub.publish_failure(data, type='gcs_retry')

    self._notify_ecosystem_bridge(vulnerability)
    self._maybe_remove_import_findings(vulnerability.id)

  def _notify_ecosystem_bridge(self, vulnerability):
    """Notify ecosystem bridges."""
    ecosystems = set()
    for affected in vulnerability.affected:
      if affected.package.ecosystem in ecosystems:
        continue

      ecosystems.add(affected.package.ecosystem)
      ecosystem_push_topic = _ECOSYSTEM_PUSH_TOPICS.get(
          affected.package.ecosystem)
      if ecosystem_push_topic:
        publisher = pubsub_v1.PublisherClient()
        cloud_project = os.environ['GOOGLE_CLOUD_PROJECT']
        push_topic = publisher.topic_path(cloud_project, ecosystem_push_topic)
        publisher.publish(
            push_topic,
            data=json.dumps(osv.vulnerability_to_dict(vulnerability)).encode())

  def _maybe_remove_import_findings(self, vuln_id: str):
    """Remove any stale import findings for a successfully processed Vuln,"""

    finding = osv.ImportFinding.get_by_id(vuln_id)
    if finding:
      logging.info('Removing stale import finding for %s', vuln_id)
      finding.key.delete()

  def _do_process_task(self, subscriber, subscription, ack_id, message,
                       done_event):
    """Process task with timeout."""
    try:
      with self._ndb_client.context():
        source_id = get_source_id(message) or message.attributes.get(
            'source', None)
        _state.source_id = source_id
        _state.bug_id = message.attributes.get('allocated_bug_id', None)

        task_type = message.attributes['type']

        # Validating that oss-fuzz-related tasks are only sent by oss-fuzz and
        # the non-oss-fuzz task is not used by oss-fuzz.
        if not source_id:
          logging.error('got message without source_id: %s', message)
        elif source_id.startswith('oss-fuzz'):
          if task_type not in ('regressed', 'fixed', 'impact', 'invalid',
                               'update-oss-fuzz'):
            logging.error('got unexpected \'%s\' task for oss-fuzz source %s',
                          task_type, source_id)
        elif task_type != 'update':
          logging.error('got unexpected \'%s\' task for non-oss-fuzz source %s',
                        task_type, source_id)

        if task_type in ('regressed', 'fixed', 'impact', 'invalid',
                         'update-oss-fuzz'):
          # TODO(michaelkedar): Remove this once the cutover is complete and the
          # subscription filter is updated.
          logging.info('Ignoring OSS-Fuzz task %s for source %s', task_type,
                       source_id)
        elif task_type == 'update':
          self._source_update(message)

        _state.source_id = None
        subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
    except Exception:
      logging.exception('Unexpected exception while processing task: ',)
      subscriber.modify_ack_deadline(
          subscription=subscription, ack_ids=[ack_id], ack_deadline_seconds=0)
    finally:
      logging.info('Ending task')
      done_event.set()

  def handle_timeout(self, subscriber, subscription, ack_id, message):
    """Handle a timeout."""
    subscriber.acknowledge(subscription=subscription, ack_ids=[ack_id])
    task_type = message.attributes['type']
    source_id = get_source_id(message) or message.attributes.get('source', None)

    logging.warning('Task %s timed out (source_id=%s)', task_type, source_id)
    if task_type in ('fixed', 'regressed'):
      oss_fuzz.handle_timeout(task_type, source_id, self._oss_fuzz_dir, message)

  def _log_task_latency(self, message):
    """Determine how long ago the task was requested.

    Log how long it took to be serviced."""
    request_time = message.attributes.get('req_timestamp')
    if request_time:
      now = int(time.time())
      request_time = int(request_time)
      latency = now - request_time

      json_fields = {
          'source': message.attributes.get('source'),
          'path': message.attributes.get('path'),
          'latency': latency,
      }
      if source_time := message.attributes.get('src_timestamp'):
        source_time = int(source_time)
        src_latency = now - source_time
        json_fields['src_latency'] = src_latency

      task_type = message.attributes['type']
      source_id = get_source_id(message) or message.attributes.get(
          'source', None)

      logging.info(
          'Task %s (source_id=%s) latency %d',
          task_type,
          source_id,
          latency,
          extra={'json_fields': json_fields})

  def loop(self):
    """Task loop."""
    subscriber = pubsub_v1.SubscriberClient()

    cloud_project = os.environ['GOOGLE_CLOUD_PROJECT']
    subscription = subscriber.subscription_path(cloud_project,
                                                TASK_SUBSCRIPTION)

    def process_task(ack_id, message):
      """Process a task."""
      osv.ensure_updated_checkout(OSS_FUZZ_GIT_URL, self._oss_fuzz_dir)
      clean_artifacts(self._oss_fuzz_dir)

      # Enforce timeout by doing the work in another thread.
      done_event = threading.Event()
      thread = threading.Thread(
          target=self._do_process_task,
          args=(subscriber, subscription, ack_id, message, done_event),
          daemon=True)
      logging.info('Creating task thread for %s', message)
      thread.start()

      done = done_event.wait(timeout=MAX_LEASE_DURATION)
      logging.info('Returned from task thread')
      if done:
        self._log_task_latency(message)
      else:
        self.handle_timeout(subscriber, subscription, ack_id, message)
        logging.warning('Timed out processing task')

    while True:
      response = subscriber.pull(subscription=subscription, max_messages=1)
      if not response.received_messages:
        continue

      message = response.received_messages[0].message
      ack_id = response.received_messages[0].ack_id

      leaser_done = threading.Event()
      leaser = _PubSubLeaserThread(subscriber, subscription, ack_id,
                                   leaser_done, MAX_LEASE_DURATION)
      leaser.start()

      try:
        process_task(ack_id, message)
      finally:
        leaser_done.set()
      leaser.join()


def main():
  parser = argparse.ArgumentParser(description='Worker')
  parser.add_argument(
      '--work_dir', help='Working directory', default=DEFAULT_WORK_DIR)
  parser.add_argument('--ssh_key_public', help='Public SSH key path')
  parser.add_argument('--ssh_key_private', help='Private SSH key path')
  parser.add_argument(
      '--redis_host', help='URL to redis instance, enables redis cache')
  parser.add_argument(
      '--redis_port', default=6379, help='Port of redis instance')
  args = parser.parse_args()

  if args.redis_host:
    osv.ecosystems.config.set_cache(
        RedisCache(args.redis_host, args.redis_port))

  osv.ecosystems.config.work_dir = args.work_dir

  # Work around kernel bug: https://gvisor.dev/issue/1765
  resource.setrlimit(resource.RLIMIT_MEMLOCK,
                     (resource.RLIM_INFINITY, resource.RLIM_INFINITY))

  subprocess.call(('service', 'docker', 'start'))

  oss_fuzz_dir = os.path.join(args.work_dir, 'oss-fuzz')

  tmp_dir = os.path.join(args.work_dir, 'tmp')
  # Temp files are on the persistent local SSD,
  # and they do not get removed when GKE sends a SIGTERM to stop the pod.
  # Manually clear the tmp_dir folder of any leftover files
  # TODO(michaelkedar): use an ephemeral disk for temp storage.
  if os.path.exists(tmp_dir):
    shutil.rmtree(tmp_dir)
  os.makedirs(tmp_dir, exist_ok=True)
  os.environ['TMPDIR'] = tmp_dir

  # Add oss-fuzz/infra to the import path so we can import from it.
  sys.path.append(os.path.join(oss_fuzz_dir, 'infra'))

  # Suppress OSS-Fuzz build error logs. These are expected as part of
  # bisection.
  logging.getLogger('helper').setLevel(logging.CRITICAL)

  osv.ensure_updated_checkout(OSS_FUZZ_GIT_URL, oss_fuzz_dir)

  ndb_client = ndb.Client()
  with ndb_client.context():
    task_runner = TaskRunner(ndb_client, oss_fuzz_dir, args.work_dir,
                             args.ssh_key_public, args.ssh_key_private)
    task_runner.loop()


if __name__ == '__main__':
  osv.logs.setup_gcp_logging('worker')
  _setup_logging_extra_info()
  main()
