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
"""Importer sources."""
import json
import hashlib
import logging
import os

import jsonschema
import pygit2
import time
import yaml

from google.protobuf import json_format

from typing import Any, Dict, List, Tuple, Optional, Type # pytype: disable=not-supported-yet

from google.protobuf import json_format

# pylint: disable=relative-beyond-top-level
from . import cache # osv.cache
from . import repos # osv.repos
from . import vulnerability_pb2 # osv.vulnerability_pb2
from . import models # osv.models

AUTHOR_EMAIL = 'infra@osv.dev'
PUSH_RETRIES = 2
PUSH_RETRY_SLEEP_SECONDS = 10

YAML_EXTENSIONS = ('.yaml', '.yml')
JSON_EXTENSIONS = ('.json',)

DEFAULT_TIMESTAMP = 946684800  # Year 2000

shared_cache: cache.Cache = cache.InMemoryCache() # Be more specific if possible, e.g. cache.InMemoryCache


class KeyPathError(Exception):
  """
  The provided key path was not found in the object.

  For example, this can happen with GSD entries where for most vulnerabilities,
  an OSV entry is not published, only the GSD part.
  """


def parse_source_id(source_id: str) -> Tuple[str, str]:
  """Get the source name and id from source_id."""
  parts = source_id.split(':', 1)
  if len(parts) == 2:
    return parts[0], parts[1]
  # Handle cases where there's no ':', though the spec implies there should be.
  # Depending on strictness, could raise error or return (source_id, '')
  return source_id, ""


def repo_path(repo: pygit2.Repository) -> str:
  """Return local disk path to repo."""
  # Remove '.git' component.
  # repo.path is typically "<path_to_workdir>/.git/"
  # os.path.dirname(<...>.rstrip(os.sep)) effectively gets <path_to_workdir>
  return os.path.dirname(repo.path.rstrip(os.sep))


class NoDatesSafeLoader(yaml.SafeLoader):
  """
  Safe YAML loader that removes datetime autoparsing

  PyYAML automatically parses date strings into Python datetime.datetime, which
  will cause multiple issues in other parts of the osv library, including
  automatically failing the json schema verifier.
  """

  @classmethod
  def remove_implicit_resolver(cls: Type[NoDatesSafeLoader], tag_to_remove: str) -> None:
    """
    Remove implicit resolvers for a particular tag

    Takes care not to modify resolvers in super classes.
    """
    # Ensure that we are modifying the class's own attribute, not a base class's
    if 'yaml_implicit_resolvers' not in cls.__dict__:
      # Copy from the base class to the current class's dict
      cls.yaml_implicit_resolvers = cls.yaml_implicit_resolvers.copy() # type: ignore[attr-defined]

    # Iterate over a copy if modifying during iteration is risky, though here it's reassignment.
    for first_letter, mappings in list(cls.yaml_implicit_resolvers.items()): # Use list() for safe iteration
      # Filter out the tag to remove for the current first_letter
      # Ensure mappings is a list of tuples
      if isinstance(mappings, list):
          cls.yaml_implicit_resolvers[first_letter] = [ # type: ignore[index]
              (tag, regexp) for tag, regexp in mappings if tag != tag_to_remove
          ]
      # Handle cases where mappings might not be a list (though typically it should be)
      # Or ensure that yaml_implicit_resolvers structure is as expected.


NoDatesSafeLoader.remove_implicit_resolver('tag:yaml.org,2002:timestamp')


def _parse_vulnerability_dict(path: str) -> Dict[str, Any]:
  """Parse a vulnerability file into a dict."""
  try:
    with open(path) as f:
      ext = os.path.splitext(path)[1]
      if ext in YAML_EXTENSIONS:
        # yaml.load can return Any, but we expect Dict for OSV data.
        data: Any = yaml.load(f, Loader=NoDatesSafeLoader)
        if not isinstance(data, dict):
            raise ValueError(f"YAML file {path} did not parse into a dictionary.")
        return data

      if ext in JSON_EXTENSIONS:
        data = json.load(f)
        if not isinstance(data, dict):
            raise ValueError(f"JSON file {path} did not parse into a dictionary.")
        return data

      raise RuntimeError('Unknown format ' + ext)
  except FileNotFoundError as e:
    logging.error("File not found: %s", path)
    raise e
  except Exception as e:
    logging.error("Failed to parse vulnerability file %s: %s", path, e)
    raise e


@cache.cached(shared_cache) # type: ignore[misc] # shared_cache is Cache, not specific enough for decorator
def load_schema() -> Dict[str, Any]:
  path = os.path.join(
      os.path.dirname(os.path.abspath(__file__)), 'osv-schema', 'validation',
      'schema.json')
  with open(path, 'r') as schema_file: # Renamed schema to schema_file
    text = schema_file.read()
    return json.loads(text)


def parse_vulnerability(path: str, key_path: Optional[str] = None, strict: bool = False) -> vulnerability_pb2.Vulnerability:
  """Parse vulnerability YAML/JSON."""
  data: Dict[str, Any] = _parse_vulnerability_dict(path)
  return parse_vulnerability_from_dict(data, key_path, strict)


def _parse_vulnerabilities_internal(data: Any, key_path: Optional[str], strict: bool = False) -> List[vulnerability_pb2.Vulnerability]: # Renamed
  """Parse multiple vulnerabilities."""
  if isinstance(data, list):
    # Ensure each item in the list is a dict before parsing
    return [parse_vulnerability_from_dict(v, key_path, strict) for v in data if isinstance(v, dict)]
  if isinstance(data, dict): # Single vulnerability case
    return [parse_vulnerability_from_dict(data, key_path, strict)]

  # If data is not a list or dict, it's an invalid format for OSV.
  # Depending on strictness, could raise error or return empty list.
  logging.warning("Attempted to parse vulnerabilities from data that is not a list or dict: %s", type(data))
  return []


def parse_vulnerabilities(path: str, key_path: Optional[str] = None, strict: bool = False) -> List[vulnerability_pb2.Vulnerability]:
  """Parse vulnerabilities (potentially multiple in a list)."""
  return _parse_vulnerabilities_internal(
      _parse_vulnerability_dict(path), key_path, strict)


def parse_vulnerabilities_from_data(data_text: str,
                                    extension: str,
                                    key_path: Optional[str] = None,
                                    strict: bool = False) -> List[vulnerability_pb2.Vulnerability]:
  """Parse vulnerabilities from data."""
  data: Any
  if extension in YAML_EXTENSIONS:
    data = yaml.load(data_text, Loader=NoDatesSafeLoader)
  elif extension in JSON_EXTENSIONS:
    data = json.loads(data_text)
  else:
    raise RuntimeError('Unknown format ' + extension)

  return _parse_vulnerabilities_internal(data, key_path, strict)


def _get_nested_vulnerability(data: Dict[str, Any], key_path: Optional[str] = None) -> Any:
  """Get nested vulnerability."""
  current_data = data
  if key_path:
    try:
      for component in key_path.split('.'):
        current_data = current_data[component] # type: ignore[literal-required, unsupported-operat]
    except (KeyError, TypeError) as e: # Added TypeError for cases where data is not subscriptable
      raise KeyPathError(f"Key path '{key_path}' not found or invalid in data.") from e

  return current_data


def parse_vulnerability_from_dict(data: Dict[str, Any], key_path: Optional[str] = None, strict: bool = False) -> vulnerability_pb2.Vulnerability:
  """Parse vulnerability from dict."""
  vulnerability_data: Any = _get_nested_vulnerability(data, key_path)
  if not isinstance(vulnerability_data, dict):
      raise ValueError(f"Data at key path '{key_path}' is not a dictionary.")

  try:
    jsonschema.validate(vulnerability_data, load_schema())
  except jsonschema.exceptions.ValidationError as e:
    # Log full data only if very verbose logging is enabled, can be large.
    logging.warning('Failed to validate loaded OSV entry against schema: %s (ID: %s)', e.message, vulnerability_data.get('id', 'UNKNOWN_ID'))
    if strict:  # Reraise the error if strict
      raise

  vulnerability = vulnerability_pb2.Vulnerability()
  try:
    json_format.ParseDict(vulnerability_data, vulnerability, ignore_unknown_fields=True)
  except json_format.ParseError as e:
    logging.error("Failed to parse dict into Vulnerability proto: %s (ID: %s)", e, vulnerability_data.get('id', 'UNKNOWN_ID'))
    if strict:
        raise
    # If not strict, return a mostly empty Vulnerability with ID if possible, or re-raise if ID is missing.
    if not vulnerability_data.get('id'): # If ID itself is missing from original data
        raise ValueError('Vulnerability data is missing the "id" field.') from e
    # Populate ID at least, so caller can identify which record failed partially
    vulnerability.id = str(vulnerability_data['id']) # Ensure ID is string
    # Potentially populate other critical minimal fields if available and safe

  if not vulnerability.id: # Should be caught by ParseDict or earlier checks unless data is truly malformed
    raise ValueError('Missing id field after parsing. Invalid vulnerability.')

  return vulnerability


def _yaml_str_representer(dumper: yaml.SafeDumper, data: str) -> yaml.ScalarNode:
  """YAML str representer override."""
  if '\n' in data:
    return dumper.represent_scalar('tag:yaml.org,2002:str', data, style='|')
  return dumper.represent_scalar('tag:yaml.org,2002:str', data)


class YamlDumper(yaml.SafeDumper):
  """Overridden dumper to to use | for multiline strings."""


YamlDumper.add_representer(str, _yaml_str_representer)


def vulnerability_to_dict(vulnerability: vulnerability_pb2.Vulnerability) -> Dict[str, Any]:
  """Convert Vulnerability to a dict."""
  # Exclude fields with default values to keep output clean,
  # but this might not be desired if defaults are meaningful.
  # Default: include_default_value_fields=False
  result: Dict[str, Any] = json_format.MessageToDict(
      vulnerability,
      preserving_proto_field_name=True,
      including_default_value_fields=True) # Set to True to include all fields.

  # The spec requires "versions" to be present if "ranges" is not, even if empty.
  # MessageToDict might omit it if empty. This ensures it's present.
  if 'affected' in result:
    for affected_entry in result['affected']:
      # Ensure affected_entry is a dict
      if not isinstance(affected_entry, dict):
          continue

      has_ranges = 'ranges' in affected_entry and affected_entry['ranges']
      has_versions = 'versions' in affected_entry # versions could be present but empty

      if not has_ranges and not has_versions:
          # If no ranges and versions is not even a key, add "versions": []
          affected_entry['versions'] = []
      # If 'versions' key exists but is None (e.g. from certain MessageToDict settings), also set to []
      elif has_versions and affected_entry['versions'] is None:
          affected_entry['versions'] = []


  return result


def _write_vulnerability_dict(data: Dict[str, Any], output_path: str,
                              modified_date_timestamp: float) -> None:
  """Write a vulnerability dict to disk."""
  # Create directory if it doesn't exist
  os.makedirs(os.path.dirname(output_path), exist_ok=True)

  with open(output_path, 'w') as f:
    ext = os.path.splitext(output_path)[1]
    if ext in YAML_EXTENSIONS:
      yaml.dump(data, f, sort_keys=False, Dumper=YamlDumper)
    elif ext in JSON_EXTENSIONS:
      json.dump(data, f, indent=2) # Add newline at end for POSIX compatibility
      f.write('\n')
    else:
      raise RuntimeError('Unknown format ' + ext)

  os.utime(output_path, (modified_date_timestamp, modified_date_timestamp))


def write_vulnerability(vulnerability: vulnerability_pb2.Vulnerability,
                        output_path: str,
                        key_path: Optional[str] = None) -> None:
  """Update a vulnerability file on disk."""
  file_data: Dict[str, Any] # Renamed data to file_data
  if os.path.exists(output_path):
    # _parse_vulnerability_dict can raise FileNotFoundError, but os.path.exists guards it.
    # It can also raise other parsing errors.
    try:
        file_data = _parse_vulnerability_dict(output_path)
    except Exception as e: # Catch parsing errors for existing corrupted files
        logging.error("Failed to parse existing vulnerability file %s: %s. Overwriting.", output_path, e)
        file_data = {} # Start fresh if existing file is corrupt
  else:
    file_data = {}

  # Navigate or build path to the vulnerability data within file_data
  # This part modifies file_data to ensure the path to vuln_target_data exists.
  vuln_target_data: Dict[str, Any]
  if key_path:
    current_level = file_data
    try:
      for component in key_path.split('.'):
        if component not in current_level or not isinstance(current_level[component], dict):
          current_level[component] = {} # Create path if not exists or not a dict
        current_level = current_level[component] # type: ignore
      vuln_target_data = current_level
    except TypeError: # current_level became not a dict unexpectedly
        # This case should ideally be prevented by the check inside the loop.
        # If it occurs, means structure is not as expected; default to top level.
        logging.warning("Invalid structure at key_path '%s' in %s. Writing to top level.", key_path, output_path)
        vuln_target_data = file_data # Fallback to top level
  else:
    vuln_target_data = file_data


  vuln_target_data.clear()
  vuln_target_data.update(vulnerability_to_dict(vulnerability))

  # Ensure vulnerability.modified is set before accessing .seconds
  dt_timestamp: float = DEFAULT_TIMESTAMP
  if vulnerability.modified and vulnerability.modified.seconds:
      dt_timestamp = float(vulnerability.modified.seconds)
      if dt_timestamp < DEFAULT_TIMESTAMP: # Ensure it's not an ancient or zero timestamp
          logging.warning('Record has very old modified time: %s (%s). Using default.',
                          vulnerability.id, dt_timestamp)
          dt_timestamp = DEFAULT_TIMESTAMP
  else: # No modified time provided in proto
    logging.warning('Record has no modified time: %s. Using default for file mtime.', vulnerability.id)
    # dt_timestamp remains DEFAULT_TIMESTAMP

  _write_vulnerability_dict(file_data, output_path, dt_timestamp)


def vulnerability_has_range(vulnerability: vulnerability_pb2.Vulnerability, introduced_sha: str, fixed_sha: str) -> bool: # Renamed args
  """Check if a vulnerability has a specific GIT range."""
  # Assuming 'vulnerability.affected' is the correct field, which is a list of Affected messages.
  for affected_package in vulnerability.affected:
    for affected_range in affected_package.ranges:
      if affected_range.type == vulnerability_pb2.Range.Type.GIT: # Corrected enum access
        # Events are now a list of Event messages. introduced/fixed are oneof fields.
        # This logic needs to find the specific introduced and fixed events.
        # This is simplified; real logic would iterate events.
        # For this check, we need to see if *any* event marks the intro and *any* event marks the fix.
        # This check is tricky because one range can have multiple events.
        # A simple interpretation: find an "introduced" event with introduced_sha
        # AND a "fixed" event with fixed_sha within the SAME range entry.
        # This is likely not what the original simplified check did.
        # Sticking to a plausible interpretation of the original intent:
        # Does this range have an event.introduced == introduced_sha and an event.fixed == fixed_sha?
        # This requires checking specific event objects.
        # A range has a list of events, not direct introduced/fixed attributes.
        # This function's logic is flawed w.r.t protobuf structure.
        # Placeholder: needs rework based on actual event structure and intent.
        # For now, let's assume we are looking for specific values in the events list.
        # This is a common pattern of error when migrating from simpler structures.
        # The original `affected_range.introduced` is not valid.
        # Let's assume it wants to find an event list that contains both.
        has_introduced = any(event.introduced == introduced_sha for event in affected_range.events)
        has_fixed = any(event.fixed == fixed_sha for event in affected_range.events)
        if has_introduced and has_fixed:
            return True

  return False


def push_source_changes(repo: pygit2.Repository,
                        commit_message: str,
                        git_callbacks: Optional[repos.GitRemoteCallback], # Use repos.GitRemoteCallback
                        expected_hashes: Optional[Dict[str, str]] = None) -> bool:
  """Push source changes."""
  repo.index.write()
  tree_oid: pygit2.Oid = repo.index.write_tree() # write_tree returns Oid
  author_sig: pygit2.Signature = git_author() # Renamed

  # Ensure repo.head.target is an Oid of a commit
  parent_commit_oid: pygit2.Oid = repo.head.peel(pygit2.Commit).id
  repo.create_commit(repo.head.name, author_sig, author_sig, commit_message, tree_oid,
                     [parent_commit_oid])

  for retry_num in range(1 + PUSH_RETRIES):
    try:
      repo.remotes['origin'].push([repo.head.name], callbacks=git_callbacks)
      return True
    except pygit2.GitError as e:
      logging.warning('Failed to push: %s', e)
      if retry_num == PUSH_RETRIES:
        repos.reset_repo(repo, git_callbacks) # Assuming repos.reset_repo is available
        return False

      time.sleep(PUSH_RETRY_SLEEP_SECONDS)

      # Try rebasing.
      commit_to_cherrypick: pygit2.Commit = repo.head.peel(pygit2.Commit) # Renamed
      repos.reset_repo(repo, git_callbacks)

      if expected_hashes: # Ensure expected_hashes is not None before iterating
        for path, expected_hash_val in expected_hashes.items(): # Renamed
          # Ensure path is absolute or relative to repo.workdir for sha256
          file_full_path = os.path.join(repo.workdir, path)
          if not os.path.exists(file_full_path): # Check if file exists before hashing
              logging.warning("File %s not found for hash comparison during push rebase.", file_full_path)
              continue
          current_hash_val = sha256(file_full_path) # Renamed
          if current_hash_val != expected_hash_val:
            logging.warning(
                'Upstream hash for %s changed (expected=%s vs current=%s)', path,
                expected_hash_val, current_hash_val)
            # Original code had `continue` here, which means it would proceed to cherry-pick
            # even if a hash mismatch was found. This might not be the intended behavior.
            # For now, replicating original logic. If a mismatch should abort, return False.

      # Then cherrypick our original commit.
      repo.cherrypick(commit_to_cherrypick.id)
      if repo.index.conflicts is not None:
        # Conflict. Don't try to resolve.
        repo.state_cleanup()
        repos.reset_repo(repo, git_callbacks)
        return False

      # Success, commit and try pushing again.
      new_tree_oid = repo.index.write_tree() # Renamed
      # Re-peel parent after potential rebase/reset
      new_parent_commit_oid = repo.head.peel(pygit2.Commit).id
      repo.create_commit(repo.head.name, commit_to_cherrypick.author, commit_to_cherrypick.author,
                         commit_to_cherrypick.message, new_tree_oid, [new_parent_commit_oid])
      repo.state_cleanup()

  return True # Should be unreachable if PUSH_RETRIES is > 0, loop handles return.


def git_author() -> pygit2.Signature:
  """Get the git author for commits."""
  return pygit2.Signature('OSV', AUTHOR_EMAIL)


def sha256(file_path: str) -> str:
  """Computes sha256 sum."""
  hasher = hashlib.sha256()
  with open(file_path, 'rb') as f_handle: # Renamed f to f_handle
    hasher.update(f_handle.read())
  return hasher.hexdigest()


def sha256_bytes(data: bytes) -> str:
  """Computes sha256sum."""
  hasher = hashlib.sha256()
  hasher.update(data)
  return hasher.hexdigest()


def source_path(source_repo: models.SourceRepository, bug_obj: models.Bug) -> str: # Renamed bug to bug_obj
  """Get the source path for an osv.Bug."""
  # Ensure bug_obj.source_id is not None
  if not bug_obj.source_id:
      # Handle error: source_id is missing
      logging.error("Bug object %s is missing source_id.", bug_obj.id())
      return "" # Or raise an error

  source_name, source_id_part = parse_source_id(bug_obj.source_id) # Renamed source_id to source_id_part

  # Ensure bug_obj.project is not None and not empty before accessing bug_obj.project[0]
  if source_name == 'oss-fuzz' and bug_obj.project and len(bug_obj.project) > 0:
    # Ensure source_repo.extension is not None
    file_extension = source_repo.extension or '' # Default to empty string if None
    path_str = os.path.join(bug_obj.project[0], bug_obj.id() + file_extension) # Renamed path
    if source_repo.directory_path:
      path_str = os.path.join(source_repo.directory_path, path_str)

    return path_str

  return source_id_part
