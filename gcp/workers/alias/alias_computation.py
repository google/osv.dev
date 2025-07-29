#!/usr/bin/env python3
# Copyright 2023 Google LLC
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
"""OSV alias computation."""
import datetime
import logging
import os

from google.cloud import ndb
from google.protobuf import json_format

import osv
from osv import gcs
import osv.logs

ALIAS_GROUP_VULN_LIMIT = 32
VULN_ALIASES_LIMIT = 5


def _update_group(bug_ids, alias_group, changed_vulns):
  """Updates the alias group in the datastore."""
  if len(bug_ids) <= 1:
    logging.info('Deleting alias group due to too few bugs: %s', bug_ids)
    for vuln_id in bug_ids:
      changed_vulns[vuln_id] = None
    alias_group.key.delete()
    return
  if len(bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Deleting alias group due to too many bugs: %s', bug_ids)
    for vuln_id in bug_ids:
      changed_vulns[vuln_id] = None
    alias_group.key.delete()
    return

  if bug_ids == alias_group.bug_ids:
    return

  alias_group.bug_ids = bug_ids
  alias_group.last_modified = datetime.datetime.now(datetime.UTC)
  alias_group.put()
  for vuln_id in bug_ids:
    changed_vulns[vuln_id] = alias_group


def _create_alias_group(bug_ids, changed_vulns):
  """Creates a new alias group in the datastore."""
  if len(bug_ids) <= 1:
    logging.info('Skipping alias group creation due to too few bugs: %s',
                 bug_ids)
    return
  if len(bug_ids) > ALIAS_GROUP_VULN_LIMIT:
    logging.info('Skipping alias group creation due to too many bugs: %s',
                 bug_ids)
    return

  new_group = osv.AliasGroup(bug_ids=bug_ids)
  new_group.last_modified = datetime.datetime.now(datetime.UTC)
  new_group.put()
  for vuln_id in bug_ids:
    changed_vulns[vuln_id] = new_group


def _compute_aliases(bug_id, visited, bug_aliases):
  """Computes all aliases for the given bug ID.
  The returned list contains the bug ID itself, all the IDs from the bug's
  raw aliases, all the IDs of bugs that have the current bug as an alias,
  and repeat for every bug encountered here."""
  to_visit = {bug_id}
  bug_ids = []
  while to_visit:
    bug_id = to_visit.pop()
    if bug_id in visited:
      continue
    visited.add(bug_id)
    bug_ids.append(bug_id)

    aliases = bug_aliases.get(bug_id, set())
    to_visit.update(aliases - visited)

  # Returns a sorted list of bug IDs, which ensures deterministic behaviour
  # and avoids unnecessary updates to the groups.
  return sorted(bug_ids)


def _update_vuln_with_group(vuln_id: str, alias_group: osv.AliasGroup | None):
  """Updates the Vulnerability in Datastore & GCS with the new alias group.
  If `alias_group` is None, assumes a preexisting AliasGroup was just deleted.
  """
  # TODO!!: check if not test instance or tests
  if False:  # pylint: disable=using-constant-test
    return
  # Get the existing vulnerability first, so we can recalculate search_indices
  bucket = gcs.get_osv_bucket()
  pb_blob = bucket.get_blob(os.path.join(gcs.VULN_PB_PATH, vuln_id + '.pb'))
  if pb_blob is None:
    if osv.Vulnerability.get_by_id(vuln_id) is not None:
      logging.error('vulnerability not in GCS - %s', vuln_id)
      # TODO(michaelkedar): send pub/sub message to reimport
    return
  try:
    vuln_proto = osv.vulnerability_pb2.Vulnerability.FromString(
        pb_blob.download_as_bytes())
  except Exception:
    logging.exception('failed to download %s protobuf from GCS', vuln_id)

  def transaction():
    vuln: osv.Vulnerability = osv.Vulnerability.get_by_id(vuln_id)
    if vuln is None:
      logging.error('vulnerability not in Datastore - %s', vuln_id)
      # TODO: Raise exception
      return
    if alias_group is None:
      modified = datetime.datetime.now(datetime.UTC)
      aliases = []
    else:
      modified = alias_group.last_modified
      aliases = alias_group.bug_ids
    aliases = sorted(set(aliases) - {vuln_id})
    vuln_proto.aliases[:] = aliases
    vuln_proto.modified.FromDatetime(modified)
    osv.ListedVulnerability.from_vulnerability(vuln_proto).put()
    vuln.modified = modified
    vuln.put()

  ndb.transaction(transaction)
  modified = vuln_proto.modified.ToDatetime(datetime.UTC)
  try:
    pb_blob.custom_time = modified
    pb_blob.upload_from_string(
        vuln_proto.SerializeToString(deterministic=True),
        content_type='application/octet-stream',
        if_generation_match=pb_blob.generation)
  except Exception:
    logging.exception('failed to upload %s protobuf to GCS', vuln_id)
    # TODO(michaelkedar): send pub/sub message to retry

  try:
    json_blob = bucket.blob(os.path.join(gcs.VULN_JSON_PATH, vuln_id + '.json'))
    json_blob.custom_time = modified
    json_data = json_format.MessageToJson(
        vuln_proto, preserving_proto_field_name=True, indent=None)
    json_blob.upload_from_string(json_data, content_type='application/json')
  except Exception:
    logging.exception('failed to upload %s json to GCS', vuln_id)
    # TODO(michaelkedar): send pub/sub message to retry


def main():
  """Updates all alias groups in the datastore by re-computing existing
  AliasGroups and creating new AliasGroups for un-computed bugs."""

  # Query for all bugs that have aliases.
  # Use (> '' OR < '') instead of (!= '') / (> '') to de-duplicate results
  # and avoid datastore emulator problems, see issue #2093
  bugs = osv.Bug.query(ndb.OR(osv.Bug.aliases > '', osv.Bug.aliases < ''))
  all_alias_group = osv.AliasGroup.query()
  allow_list = {
      allow_entry.bug_id for allow_entry in osv.AliasAllowListEntry.query()
  }
  deny_list = {
      deny_entry.bug_id for deny_entry in osv.AliasDenyListEntry.query()
  }

  # Mapping of ID to a set of all aliases for that bug,
  # including its raw aliases and bugs that it is referenced in as an alias.
  bug_aliases = {}

  # For each bug, add its aliases to the maps and ignore invalid bugs.
  for bug in bugs:
    if bug.db_id in deny_list:
      continue
    if len(bug.aliases) > VULN_ALIASES_LIMIT and bug.db_id not in allow_list:
      logging.info('%s has too many listed aliases, skipping computation.',
                   bug.db_id)
      continue
    if bug.status != osv.BugStatus.PROCESSED:
      continue
    for alias in bug.aliases:
      bug_aliases.setdefault(bug.db_id, set()).add(alias)
      bug_aliases.setdefault(alias, set()).add(bug.db_id)

  visited = set()

  # Keep track of vulnerabilities that have been modified, to update GCS later.
  # `None` means the AliasGroup has been removed.
  changed_vulns: dict[str, osv.AliasGroup | None] = {}

  # For each alias group, re-compute the bug IDs in the group and update the
  # group with the computed bug IDs.
  for alias_group in all_alias_group:
    bug_id = alias_group.bug_ids[0]  # AliasGroups contain more than one bug.
    # If the bug has already been counted in a different alias group,
    # we delete the original one to merge two alias groups.
    if bug_id in visited:
      for vuln_id in alias_group.bug_ids:
        if vuln_id not in changed_vulns:
          changed_vulns[vuln_id] = None
      alias_group.key.delete()
      continue
    bug_ids = _compute_aliases(bug_id, visited, bug_aliases)
    _update_group(bug_ids, alias_group, changed_vulns)

  # For each bug ID that has not been visited, create new alias groups.
  for bug_id in bug_aliases:
    if bug_id not in visited:
      bug_ids = _compute_aliases(bug_id, visited, bug_aliases)
      _create_alias_group(bug_ids, changed_vulns)

  # For each updated vulnerability, update them in Datastore & GCS
  for vuln_id, alias_group in changed_vulns.items():
    _update_vuln_with_group(vuln_id, alias_group)


if __name__ == '__main__':
  _ndb_client = ndb.Client()
  osv.logs.setup_gcp_logging('alias')
  with _ndb_client.context():
    main()
