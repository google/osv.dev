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
"""Datastore types."""

import datetime
import enum
import logging
import re
import os
from urllib.parse import urlparse
from typing import Any, Dict, List, Optional, Set, Type, TypeVar, Union, Self # pytype: disable=not-supported-yet

from google.cloud import ndb
from google.protobuf import json_format, message
from google.protobuf import timestamp_pb2
from osv import importfinding_pb2


# pylint: disable=relative-beyond-top-level
from . import bug # osv.bug
from . import ecosystems # osv.ecosystems
from . import purl_helpers # osv.purl_helpers
from . import semver_index # osv.semver_index
from . import sources # osv.sources
from . import vulnerability_pb2 # osv.vulnerability_pb2

SCHEMA_VERSION = '1.6.0'

_MAX_GIT_VERSIONS_TO_INDEX = 5000

# Generic type for NDB models, used for cls methods.
_M = TypeVar('_M', bound='ndb.Model')


def _check_valid_severity(prop: ndb.Property, value: str) -> None:
  """Check valid severity."""
  del prop

  if value not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
    raise ValueError('Invalid severity: ' + value)


def _check_valid_range_type(prop: ndb.Property, value: str) -> None:
  """Check valid range type."""
  del prop

  if value not in ('GIT', 'SEMVER', 'ECOSYSTEM'):
    raise ValueError('Invalid range type: ' + value)


def _check_valid_event_type(prop: ndb.Property, value: str) -> None:
  """Check valid event type."""
  del prop

  if value not in ('introduced', 'fixed', 'last_affected', 'limit'):
    raise ValueError('Invalid event type: ' + value)


def utcnow() -> datetime.datetime:
  """For mocking."""
  return datetime.datetime.now(datetime.UTC)


def _get_purl_indexes(affected_packages: List[AffectedPackage]) -> List[str]:
  """Get list of purls from affected packages, with and without qualifiers"""
  resulting_set: Set[str] = set()
  for pkg in affected_packages:
    if pkg.package and pkg.package.purl: # Added check for pkg.package
      resulting_set.add(pkg.package.purl)
      if '?' in pkg.package.purl:
        resulting_set.add(pkg.package.purl.split('?')[0])
  return sorted(list(resulting_set)) # Return sorted list


def _repo_name(repo_url: str) -> str:
  # https://github.com/eclipse-openj9/openj9 -> openj9
  url = urlparse(repo_url)
  # Corrected: os.path.basename to get the last part of the path
  name_with_git = os.path.basename(url.path)
  name = name_with_git.rstrip(".git")
  # Handle cases like empty name if URL is just "https://github.com/"
  return name if name else ''


def _maybe_strip_repo_prefixes(versions: List[str],
                               repo_urls: List[str]) -> List[str]:
  """Try to strip the repo name from tags prior to normalizing.

  There are some particularly regex-unfriendly tag names that prefix the
  reponame that end in a number, like "openj9-0.8.0", resulting in an
  incorrectly normalized version.
  """
  # Initialize with original versions to avoid modifying input list directly
  # if no repo_urls are provided or no changes are made.
  repo_stripped_versions: List[str] = list(versions)

  for repo_url in repo_urls:
    assumed_reponame = _repo_name(repo_url).lower()
    if not assumed_reponame: # Skip if repo name could not be determined
        continue
    # Apply stripping for each version based on the current assumed_reponame
    current_stripped_versions = []
    for v in repo_stripped_versions: # Use the current state of stripped versions
        # Ensure lstrip is only applied if the prefix matches
        temp_v = v
        if temp_v.lower().startswith(assumed_reponame):
            temp_v = temp_v[len(assumed_reponame):]
        if temp_v.startswith("-"):
            temp_v = temp_v[1:]
        current_stripped_versions.append(temp_v)
    repo_stripped_versions = current_stripped_versions


  return repo_stripped_versions


class IDCounter(ndb.Model):
  """Counter for ID allocations."""
  # Next ID to allocate.
  next_id: int = ndb.IntegerProperty()


class AffectedCommits(ndb.Model):
  """AffectedCommits entry."""
  MAX_COMMITS_PER_ENTITY = 10000

  # The main bug ID.
  bug_id: str = ndb.StringProperty()
  # The commit hash.
  commits: list[bytes] = ndb.BlobProperty(repeated=True, indexed=True)
  # Whether or not the bug is public.
  public: bool = ndb.BooleanProperty()
  # The page for this batch of commits.
  page: int = ndb.IntegerProperty(indexed=False)


class RegressResult(ndb.Model):
  """Regression results."""
  # The commit hash.
  commit: str = ndb.StringProperty(default='')
  # Vulnerability summary.
  summary: str = ndb.TextProperty()
  # Vulnerability details.
  details: str = ndb.TextProperty()
  # Error (if any).
  error: str = ndb.StringProperty()
  # OSS-Fuzz issue ID.
  issue_id: str = ndb.StringProperty()
  # Project for the bug.
  project: str = ndb.StringProperty()
  # Package ecosystem for the project.
  ecosystem: str = ndb.StringProperty()
  # Repo URL.
  repo_url: str = ndb.StringProperty()
  # Severity of the bug.
  severity: str = ndb.StringProperty(validator=_check_valid_severity)
  # Reference URLs.
  reference_urls: list[str] = ndb.StringProperty(repeated=True)
  # Source timestamp.
  timestamp: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.UTC)


class FixResult(ndb.Model):
  """Fix results."""
  # The commit hash.
  commit: str = ndb.StringProperty(default='')
  # Vulnerability summary.
  summary: str = ndb.TextProperty()
  # Vulnerability details.
  details: str = ndb.TextProperty()
  # Error (if any).
  error: str = ndb.StringProperty()
  # OSS-Fuzz issue ID.
  issue_id: str = ndb.StringProperty()
  # Project for the bug.
  project: str = ndb.StringProperty()
  # Package ecosystem for the project.
  ecosystem: str = ndb.StringProperty()
  # Repo URL.
  repo_url: str = ndb.StringProperty()
  # Severity of the bug.
  severity: str = ndb.StringProperty(validator=_check_valid_severity)
  # Reference URLs.
  reference_urls: list[str] = ndb.StringProperty(repeated=True)
  # Source timestamp.
  timestamp: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.UTC)


class AffectedEvent(ndb.Model):
  """Affected event."""
  type: str = ndb.StringProperty(validator=_check_valid_event_type)
  value: str = ndb.StringProperty()


class AffectedRange2(ndb.Model):
  """Affected range."""
  # Type of range.
  type: str = ndb.StringProperty(validator=_check_valid_range_type)
  # Repo URL.
  repo_url: str = ndb.StringProperty()
  # Events.
  events: list[AffectedEvent] = ndb.LocalStructuredProperty(
      AffectedEvent, repeated=True)


class SourceOfTruth(enum.IntEnum):
  """Source of truth."""
  NONE = 0
  # Internal to OSV (e.g. private OSS-Fuzz bugs).
  INTERNAL = 1
  # Vulnerabilities that are available in a public repo.
  SOURCE_REPO = 2


class Package(ndb.Model):
  """Package."""
  ecosystem: str = ndb.StringProperty()
  name: str = ndb.StringProperty()
  purl: str = ndb.StringProperty()


class Severity(ndb.Model):
  """Severity."""
  type: str = ndb.StringProperty()
  score: str = ndb.StringProperty()


class AffectedPackage(ndb.Model):
  """Affected packages."""
  # The affected package identifier.
  package: Package = ndb.StructuredProperty(Package)
  # The list of affected ranges.
  ranges: list[AffectedRange2] = ndb.LocalStructuredProperty(
      AffectedRange2, repeated=True)
  # The list of explicit affected versions.
  versions: list[str] = ndb.TextProperty(repeated=True)
  # Database specific metadata.
  database_specific: dict = ndb.JsonProperty()
  # Ecosystem specific metadata.
  ecosystem_specific: dict = ndb.JsonProperty()
  # Severity of the bug.
  severities: list[Severity] = ndb.LocalStructuredProperty(
      Severity, repeated=True)


class Credit(ndb.Model):
  """Credits."""
  name: str = ndb.StringProperty()
  contact: list[str] = ndb.StringProperty(repeated=True)
  type: str = ndb.StringProperty()


class Bug(ndb.Model):
  """Bug entity."""
  OSV_ID_PREFIX = 'OSV-'
  # Very large fake version to use when there is no fix available.
  _NOT_FIXED_SEMVER = '999999.999999.999999'

  # Display ID as used by the source database. The full qualified database that
  # OSV tracks this as may be different.
  db_id: str = ndb.StringProperty()
  # Other IDs this bug is known as.
  aliases: list[str] = ndb.StringProperty(repeated=True)
  # Related IDs.
  related: list[str] = ndb.StringProperty(repeated=True)
  # Raw upstream vulnerability IDs from the source - does not include
  # exhaustive transitive upstreams
  upstream_raw: list[str] = ndb.StringProperty(repeated=True)
  # Status of the bug.
  status: int = ndb.IntegerProperty()
  # Timestamp when Bug was allocated.
  timestamp: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.UTC)
  # When the entry was last edited.
  last_modified: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.UTC)
  # Last modified field of the original imported file
  import_last_modified: datetime.datetime = ndb.DateTimeProperty(
      tzinfo=datetime.UTC)
  # When the entry was withdrawn.
  withdrawn: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.UTC)
  # The source identifier.
  # For OSS-Fuzz, this oss-fuzz:<ClusterFuzz testcase ID>.
  # For others this is <source>:<path/to/source>.
  source_id: str = ndb.StringProperty()
  # The main fixed commit (from bisection).
  fixed: str = ndb.StringProperty(default='')
  # The main regressing commit (from bisection).
  regressed: str = ndb.StringProperty(default='')
  # List of affected versions.
  affected: list[str] = ndb.TextProperty(repeated=True)
  # List of normalized versions indexed for fuzzy matching.
  affected_fuzzy: list[str] = ndb.StringProperty(repeated=True)
  # OSS-Fuzz issue ID.
  issue_id: str = ndb.StringProperty()
  # Package URL for this package.
  purl: List[str] = ndb.StringProperty(repeated=True)
  # Project/package name for the bug.
  project: List[str] = ndb.StringProperty(repeated=True)
  # Package ecosystem for the project.
  ecosystem: List[str] = ndb.StringProperty(repeated=True)
  # Summary for the bug.
  summary: str = ndb.TextProperty()
  # Vulnerability details.
  details: str = ndb.TextProperty()
  # Severity of the bug.
  severities: List[Severity] = ndb.LocalStructuredProperty(
      Severity, repeated=True)
  # Credits for the bug.
  credits: List[Credit] = ndb.LocalStructuredProperty(Credit, repeated=True)
  # Whether or not the bug is public (OSS-Fuzz only).
  public: bool = ndb.BooleanProperty()
  # Reference URL types (dict of url -> type).
  reference_url_types: Dict[str, str] = ndb.JsonProperty()
  # Search indices (auto-populated)
  search_indices: List[str] = ndb.StringProperty(repeated=True)
  # Whether or not the bug has any affected versions (auto-populated).
  has_affected: bool = ndb.BooleanProperty()
  # Source of truth for this Bug.
  source_of_truth: SourceOfTruth = ndb.IntegerProperty(
      default=SourceOfTruth.INTERNAL)
  # Whether the bug is fixed (indexed for querying).
  is_fixed: bool = ndb.BooleanProperty()
  # Database specific.
  database_specific: Dict[str, Any] = ndb.JsonProperty()
  # Normalized SEMVER fixed indexes for querying.
  semver_fixed_indexes: List[str] = ndb.StringProperty(repeated=True)
  # Affected packages and versions.
  affected_packages: List[AffectedPackage] = ndb.LocalStructuredProperty(
      AffectedPackage, repeated=True)
  # The source of this Bug.
  source: str = ndb.StringProperty()

  def id(self) -> str:
    """Get the bug ID."""
    # Ensure key is populated, which happens in _pre_put_hook or by NDB loading.
    # This method might be called before _pre_put_hook in some scenarios (e.g. direct instantiation and use).
    # However, typical usage involves NDB loading or saving, which handles key creation.
    if self.db_id:
      return self.db_id

    # TODO(ochang): Remove once all existing bugs have IDs migrated.
    # Check if self.key exists before calling id() on it
    if self.key and re.match(r'^\d+', self.key.id()): # type: ignore
      return self.OSV_ID_PREFIX + self.key.id() # type: ignore

    if self.key:
        return self.key.id() # type: ignore

    # Fallback or error if key is not set and db_id is not available.
    # This case should ideally not happen if the entity is managed by NDB.
    # For robustness, one might raise an error or return a default/placeholder.
    # Given the original logic, it implies key.id() would be available.
    # If self.key is None here, it means the entity is not yet persisted or loaded.
    # This could be problematic. For now, trust that NDB handles key population.
    # If an error occurs due to self.key being None, it indicates an issue with entity lifecycle management.
    raise ValueError("Bug entity has no ID (db_id or key)")


  @property
  def repo_url(self: Self) -> Optional[str]:
    """Repo URL. Assumes there is only ever one repo URL per advisory."""
    for affected_package in self.affected_packages:
      for affected_range in affected_package.ranges:
        if affected_range.repo_url:
          return affected_range.repo_url

    return None

  @classmethod
  def get_by_id(cls: Type[Self], vuln_id: str, *args: Any, **kwargs: Any) -> Optional[Self]:
    """Overridden get_by_id to handle OSV allocated IDs."""
    # Querying for db_id
    # NDB Generic type issue, cast to specific type
    result: Optional[Self] = cls.query(cls.db_id == vuln_id).get() # type: ignore
    if result:
      return result

    # TODO(ochang): Remove once all exsting bugs have IDs migrated.
    original_vuln_id = vuln_id
    if vuln_id.startswith(cls.OSV_ID_PREFIX):
      vuln_id = vuln_id[len(cls.OSV_ID_PREFIX):]

    # Call super().get_by_id with the potentially modified vuln_id
    # and also try with the original_vuln_id if the first attempt fails,
    # covering cases where the ID might or might not have the prefix in the key.
    # NDB's get_by_id is a direct key lookup, so if the ID format in the key
    # is inconsistent, this dual check might be needed.
    # However, the standard is that the key should store the non-prefixed ID if it's numeric.
    instance = super(Bug, cls).get_by_id(vuln_id, *args, **kwargs)
    if instance:
        return instance
    # If the ID was prefixed and the above failed, it implies the key might actually store the prefixed ID.
    # This is unlikely given the typical NDB keying strategy but added for completeness if migration was partial.
    if original_vuln_id != vuln_id:
        instance = super(Bug, cls).get_by_id(original_vuln_id, *args, **kwargs)
        if instance:
            return instance

    return None


  def _tokenize(self, value: str) -> Set[str]:
    """Tokenize value for indexing."""
    if not value:
      return set() # Return empty set for empty value

    value_lower = value.lower()

    # Deconstructs the id given into parts by retrieving parts that are
    # alphanumeric.
    # This addresses special cases like SUSE that include ':' in their id suffix
    tokens: Set[str] = {token for token in re.split(r'\W+', value_lower) if token}
    tokens.add(value_lower)

    # Add subsection combinations from id (split at '-') in the search indices
    # Specifically addresses situation in which UBUNTU-CVE-XXXs don't show up
    # when searching for the CVE-XXX.
    # e.g. `a-b-c-d' becomes ['a-b', 'b-c', 'c-d', 'a-b-c', 'b-c-d', 'a-b-c-d']
    # Does not account for combinations with the suffix sections ':' like SUSE
    parts = value_lower.split('-')
    num_parts = len(parts)
    for length in range(2, num_parts + 1):
      for i in range(num_parts - length + 1):
        sub_parts = parts[i:i + length]
        combo = '-'.join(sub_parts)
        tokens.add(combo)
    return tokens

  def _pre_put_hook(self) -> None:  # pylint: disable=arguments-differ
    """Pre-put hook for populating search indices."""
    search_indices_set: Set[str] = set()

    # Ensure self.key is set before calling self.id() if self.id() relies on self.key
    # NDB typically calls _pre_put_hook before assigning the final key if it's auto-generated.
    # However, our self.id() logic tries db_id first.
    # If db_id is not set and key is not set, self.id() will raise an error.
    # This hook should ideally run *after* the key is definitively set if db_id is not primary.
    # Assuming db_id is usually present, or key is set by the time this is called.
    current_id = self.id() # This might fail if key and db_id are not set.
    search_indices_set.update(self._tokenize(current_id))


    for pkg in self.affected_packages:
      # Ensure pkg.package is not None before accessing its attributes
      if pkg.package:
        # Set PURL if it wasn't provided.
        if not pkg.package.purl:
          # Ensure ecosystem and name are not None
          if pkg.package.ecosystem and pkg.package.name:
            pkg.package.purl = purl_helpers.package_to_purl(
                ecosystems.normalize(pkg.package.ecosystem), pkg.package.name)

    self.project = sorted(list(set(
        pkg.package.name for pkg in self.affected_packages if pkg.package and pkg.package.name
    )))

    # self.ecosystem is a List[str], ensure 'GIT' is added correctly if repo_url exists
    current_repo_url = self.repo_url # Use the property
    current_ecosystems_list = self.ecosystem if self.ecosystem else []
    if current_repo_url and 'GIT' in current_ecosystems_list: # Check if 'GIT' is in the list
      if current_repo_url not in self.project: # Add if not already present
          self.project.append(current_repo_url)
          self.project.sort()


    ecosystems_set_from_packages: Set[str] = {
        pkg.package.ecosystem
        for pkg in self.affected_packages
        if pkg.package and pkg.package.ecosystem
    }

    # Only attempt to add the Git ecosystem if
    # there are no existing ecosystems present
    if not ecosystems_set_from_packages:
      for pkg in self.affected_packages:
        for r_item in pkg.ranges: # Renamed r to r_item to avoid conflict
          if r_item.type == 'GIT':
            ecosystems_set_from_packages.add('GIT')
            break
        if 'GIT' in ecosystems_set_from_packages:
          break

    # If a withdrawn record has no affected package,
    # assign an '[EMPTY]' ecosystem value for export.
    if not ecosystems_set_from_packages and self.withdrawn: # Added check for withdrawn
      ecosystems_set_from_packages.add('[EMPTY]')

    # For all ecosystems that specify a specific version with colon,
    # also add the base name
    normalized_ecosystems_set: Set[str] = {ecosystems.normalize(x) for x in ecosystems_set_from_packages}
    ecosystems_set_from_packages.update(normalized_ecosystems_set)


    # Expand the set to include all ecosystem variants.
    # Ensure add_matching_ecosystems returns a Set[str]
    ecosystems_set_from_packages = ecosystems.add_matching_ecosystems(ecosystems_set_from_packages)

    self.ecosystem = sorted(list(ecosystems_set_from_packages))

    self.purl = _get_purl_indexes(self.affected_packages) # Already sorted by the helper

    for proj in self.project: # Renamed project to proj
      search_indices_set.update(self._tokenize(proj))

    for eco in self.ecosystem: # Renamed ecosystem to eco
      search_indices_set.update(self._tokenize(eco))

    for alias_item in self.aliases: # Renamed alias to alias_item
      search_indices_set.update(self._tokenize(alias_item))

    # Please note this will not include exhaustive transitive upstream
    # so may not appear for all cases.
    for upstream_item in self.upstream_raw: # Renamed upstream to upstream_item
      search_indices_set.update(self._tokenize(upstream_item))

    for affected_pkg_item in self.affected_packages: # Renamed affected_package
      for affected_range_item in affected_pkg_item.ranges: # Renamed affected_range
        if affected_range_item.repo_url and affected_range_item.repo_url != '':
          # Ensure URL has // before splitting
          if '//' in affected_range_item.repo_url:
            url_no_https = affected_range_item.repo_url.split('//', 1)[1]
            # Ensure url_no_https has / before splitting
            if '/' in url_no_https:
                repo_url_indices_parts = url_no_https.split('/', 1)[1:] # remove domain, take rest
                repo_url_indices = repo_url_indices_parts[0].split('/') if repo_url_indices_parts else []
            else: # Handle cases like "domain.com" with no path
                repo_url_indices = []

            repo_url_indices.append(affected_range_item.repo_url)  # add full url
            repo_url_indices.append(url_no_https)  # add url without https://
            search_indices_set.update(repo_url_indices)


    self.search_indices = sorted(list(search_indices_set))
    self.affected_fuzzy = []
    self.semver_fixed_indexes = []
    self.has_affected = False
    self.is_fixed = False

    for affected_pkg_item in self.affected_packages: # Renamed
      # Indexes used for querying by exact version.
      # Ensure package.ecosystem is not None
      ecosystem_helper: Optional[ecosystems.Ecosystem] = None
      if affected_pkg_item.package and affected_pkg_item.package.ecosystem:
          ecosystem_helper = ecosystems.get(affected_pkg_item.package.ecosystem)

      if ecosystem_helper and ecosystem_helper.supports_ordering:
        # No need to normalize if the ecosystem is supported.
        self.affected_fuzzy.extend(affected_pkg_item.versions)
      else:
        # Check if package and ecosystem are None or empty before len(versions)
        is_git_like = False
        if affected_pkg_item.package and not affected_pkg_item.package.ecosystem:
            is_git_like = True

        if (is_git_like and
            len(affected_pkg_item.versions) > _MAX_GIT_VERSIONS_TO_INDEX):
          logging.info(
              'Skipping indexing of git versions for %s '
              'as there are too many (%s).', self.db_id,
              len(affected_pkg_item.versions))
        else:
          # Ensure all elements in list comprehension for _maybe_strip_repo_prefixes are valid
          repo_urls_for_strip = [
              range_item.repo_url for range_item in affected_pkg_item.ranges if range_item.repo_url
          ]
          self.affected_fuzzy.extend(
              bug.normalize_tags(
                  _maybe_strip_repo_prefixes(
                      affected_pkg_item.versions,
                      repo_urls_for_strip)))


      self.has_affected = self.has_affected or bool(affected_pkg_item.versions)

      for affected_range_item in affected_pkg_item.ranges: # Renamed
        fixed_version: Optional[str] = None
        for event_item in affected_range_item.events: # Renamed
          # Index used to query by fixed/unfixed.
          if event_item.type == 'limit':
            self.is_fixed = True
            fixed_version = event_item.value

          if event_item.type == 'fixed':
            self.is_fixed = True
            fixed_version = event_item.value

        if affected_range_item.type == 'SEMVER':
          # Indexes used for querying by semver.
          fixed_val: str = fixed_version or self._NOT_FIXED_SEMVER
          self.semver_fixed_indexes.append(semver_index.normalize(fixed_val))

        self.has_affected = self.has_affected or (affected_range_item.type in ('SEMVER', 'ECOSYSTEM'))

    self.affected_fuzzy = sorted(list(set(self.affected_fuzzy)))


    if not self.last_modified:
      self.last_modified = utcnow()

    if self.source_id:
      # Ensure parse_source_id returns two values
      parsed_source, _ = sources.parse_source_id(self.source_id)
      if parsed_source: # Check if source was successfully parsed
          self.source = parsed_source


    if not self.source:
      # Provide db_id in error message if available
      err_msg_id = self.db_id or "(unknown ID)"
      raise ValueError(f'Source not specified for Bug {err_msg_id}.')


    if not self.db_id:
      raise ValueError('DB ID not specified for Bug.')

    # Key creation logic
    # This part of NDB lifecycle can be tricky. _pre_put_hook is called before an ID is auto-assigned.
    # If the key is based on db_id, it should be okay.
    # If self.key is already set (e.g. when loading an entity), this logic is skipped.
    if not self.key:
      # Ensure self.source is valid before using it with get_source_repository
      if not self.source:
          raise ValueError(f"Cannot create key for Bug {self.db_id}: source is not set.")
      source_repo_instance: Optional[SourceRepository] = get_source_repository(self.source) # Renamed
      if not source_repo_instance:
        raise ValueError(f'{self.db_id} has invalid source {self.source}')

      if source_repo_instance.db_prefix and not any(
          self.db_id.startswith(prefix) for prefix in source_repo_instance.db_prefix): # type: ignore
        raise ValueError(
            f'{self.db_id} has invalid prefix for source {self.source}')

      self.key = ndb.Key(Bug, self.db_id) # type: ignore

    if self.withdrawn:
      self.status = bug.BugStatus.INVALID.value # Use .value for enum

  def update_from_vulnerability(self, vulnerability: vulnerability_pb2.Vulnerability) -> None:
    """Set fields from vulnerability. Does not set the ID."""
    self.summary = vulnerability.summary
    self.details = vulnerability.details
    self.reference_url_types = {
        ref.url: vulnerability_pb2.Reference.Type.Name(ref.type)
        for ref in vulnerability.references
    }

    if vulnerability.HasField('modified'):
      self.last_modified = vulnerability.modified.ToDatetime(tz=datetime.timezone.utc) # Ensure tz-aware
    if vulnerability.HasField('published'):
      self.timestamp = vulnerability.published.ToDatetime(tz=datetime.timezone.utc) # Ensure tz-aware
    if vulnerability.HasField('withdrawn'):
      self.withdrawn = vulnerability.withdrawn.ToDatetime(tz=datetime.timezone.utc) # Ensure tz-aware
    else:
      self.withdrawn = None # Explicitly set to None if not present

    self.aliases = list(vulnerability.aliases)
    self.related = list(vulnerability.related)
    self.upstream_raw = list(vulnerability.upstream) # New field in proto

    self.affected_packages = []
    for affected_pkg_proto in vulnerability.affected: # Renamed
      current_affected_pkg = AffectedPackage()
      current_affected_pkg.package = Package(
          name=affected_pkg_proto.package.name,
          ecosystem=affected_pkg_proto.package.ecosystem,
          purl=affected_pkg_proto.package.purl)
      current_affected_pkg.ranges = []

      for affected_range_proto in affected_pkg_proto.ranges: # Renamed
        current_range_obj = AffectedRange2( # Renamed
            type=vulnerability_pb2.Range.Type.Name(affected_range_proto.type),
            repo_url=affected_range_proto.repo, # repo is field name in proto
            events=[])

        for evt_proto in affected_range_proto.events: # Renamed
          # Determine which oneof field is set
          event_type_str: Optional[str] = None
          event_value_str: Optional[str] = None

          if evt_proto.HasField('introduced'): # Check before accessing
            event_type_str = 'introduced'
            event_value_str = evt_proto.introduced
          elif evt_proto.HasField('fixed'):
            event_type_str = 'fixed'
            event_value_str = evt_proto.fixed
          elif evt_proto.HasField('last_affected'):
            event_type_str = 'last_affected'
            event_value_str = evt_proto.last_affected
          elif evt_proto.HasField('limit'):
            event_type_str = 'limit'
            event_value_str = evt_proto.limit

          if event_type_str and event_value_str is not None: # Ensure value is not None
              current_range_obj.events.append(
                  AffectedEvent(type=event_type_str, value=event_value_str))

        current_affected_pkg.ranges.append(current_range_obj)

      current_affected_pkg.versions = list(affected_pkg_proto.versions)
      # Ensure database_specific and ecosystem_specific are dicts
      if affected_pkg_proto.HasField('database_specific'):
          current_affected_pkg.database_specific = json_format.MessageToDict(
              affected_pkg_proto.database_specific,
              preserving_proto_field_name=True)
      else:
          current_affected_pkg.database_specific = {}


      if affected_pkg_proto.HasField('ecosystem_specific'):
          current_affected_pkg.ecosystem_specific = json_format.MessageToDict(
              affected_pkg_proto.ecosystem_specific,
              preserving_proto_field_name=True)
      else:
          current_affected_pkg.ecosystem_specific = {}


      current_affected_pkg.severities = []
      for severity_proto in affected_pkg_proto.severity: # Renamed
        current_affected_pkg.severities.append(
            Severity(
                type=vulnerability_pb2.Severity.Type.Name(severity_proto.type),
                score=severity_proto.score))

      self.affected_packages.append(current_affected_pkg)

    self.severities = []
    for severity_proto in vulnerability.severity: # Renamed
      self.severities.append(
          Severity(
              type=vulnerability_pb2.Severity.Type.Name(severity_proto.type),
              score=severity_proto.score))

    self.credits = []
    for credit_proto in vulnerability.credits: # Renamed
      cr = Credit(name=credit_proto.name, contact=list(credit_proto.contact))
      if credit_proto.type: # type is optional in proto
        cr.type = vulnerability_pb2.Credit.Type.Name(credit_proto.type)
      self.credits.append(cr)

    if vulnerability.HasField('database_specific'):
      self.database_specific = json_format.MessageToDict(
          vulnerability.database_specific, preserving_proto_field_name=True)
    else:
        self.database_specific = {}


  def to_vulnerability_minimal(self) -> vulnerability_pb2.Vulnerability:
    """Convert to Vulnerability proto (minimal)."""
    modified_ts: Optional[timestamp_pb2.Timestamp] = None
    if self.last_modified:
      modified_ts = timestamp_pb2.Timestamp()
      modified_ts.FromDatetime(self.last_modified)

    return vulnerability_pb2.Vulnerability(id=self.id(), modified=modified_ts)

  def to_vulnerability(self,
                       include_source: bool = False,
                       include_alias: bool = True,
                       include_upstream: bool = True
                      ) -> vulnerability_pb2.Vulnerability:
    """Convert to Vulnerability proto."""
    affected_protos: List[vulnerability_pb2.Affected] = []

    source_link_str: Optional[str] = None # Renamed
    if self.source and include_source:
      source_repo_instance = get_source_repository(self.source) # Renamed
      if source_repo_instance and source_repo_instance.link:
        # Assuming sources.source_path is compatible with SourceRepository and Bug types
        source_path_str = sources.source_path(source_repo_instance, self) # Renamed
        if source_path_str: # Ensure source_path is not None
             source_link_str = source_repo_instance.link + source_path_str


    if self.affected_packages:
      for affected_pkg_item in self.affected_packages: # Renamed
        range_protos: List[vulnerability_pb2.Range] = [] # Renamed
        for affected_range_item in affected_pkg_item.ranges: # Renamed
          event_protos: List[vulnerability_pb2.Event] = [] # Renamed
          for event_item in affected_range_item.events: # Renamed
            # Ensure event.type is a valid key for kwargs
            # The original code {event.type: event.value} is okay if event.type is always 'introduced', 'fixed', etc.
            kwargs_dict = {event_item.type: event_item.value}
            event_protos.append(vulnerability_pb2.Event(**kwargs_dict))

          current_range_proto = vulnerability_pb2.Range( # Renamed
              type=vulnerability_pb2.Range.Type.Value(affected_range_item.type), # type: ignore
              repo=affected_range_item.repo_url,
              events=event_protos)

          range_protos.append(current_range_proto)

        # Ensure package name and ecosystem are not None before creating Package proto
        pkg_name = affected_pkg_item.package.name if affected_pkg_item.package else ""
        pkg_ecosystem = affected_pkg_item.package.ecosystem if affected_pkg_item.package else ""
        pkg_purl = affected_pkg_item.package.purl if affected_pkg_item.package else ""


        current_affected_proto = vulnerability_pb2.Affected( # Renamed
            package=vulnerability_pb2.Package(
                name=pkg_name,
                ecosystem=pkg_ecosystem,
                purl=pkg_purl),
            ranges=range_protos,
            versions=affected_pkg_item.versions)


        # Converted CVE records have no package defined.
        # Avoid exporting an empty package field.
        if not current_affected_proto.package.ListFields():
          current_affected_proto.ClearField("package")

        if affected_pkg_item.database_specific:
          # Ensure current_affected_proto.database_specific is a MessageMapContainer
          # The update method works for protobuf MessageMap.
          current_affected_proto.database_specific.update(affected_pkg_item.database_specific)


        if source_link_str:
          current_affected_proto.database_specific['source'] = source_link_str


        if affected_pkg_item.ecosystem_specific:
          current_affected_proto.ecosystem_specific.update(affected_pkg_item.ecosystem_specific)


        for severity_entry in affected_pkg_item.severities: # Renamed
          current_affected_proto.severity.append(
              vulnerability_pb2.Severity(
                  type=vulnerability_pb2.Severity.Type.Value(severity_entry.type), # type: ignore
                  score=severity_entry.score))

        affected_protos.append(current_affected_proto)

    details_str = self.details # Renamed

    modified_ts: Optional[timestamp_pb2.Timestamp] = None # Renamed
    # Note that there is further possible mutation of this field below when
    # `include_alias` is True or `include_upstream` is True
    if self.last_modified:
      modified_ts = timestamp_pb2.Timestamp()
      modified_ts.FromDatetime(self.last_modified)


    withdrawn_ts: Optional[timestamp_pb2.Timestamp] = None # Renamed
    if self.withdrawn:
      withdrawn_ts = timestamp_pb2.Timestamp()
      withdrawn_ts.FromDatetime(self.withdrawn)


    published_ts = timestamp_pb2.Timestamp() # Renamed
    # Ensure self.timestamp is not None
    if self.timestamp:
        published_ts.FromDatetime(self.timestamp)
    # Else, published_ts will be empty (epoch 0), which might be acceptable or need specific handling.

    reference_protos: List[vulnerability_pb2.Reference] = [] # Renamed
    if self.reference_url_types:
      for url_str, url_type_str in self.reference_url_types.items(): # Renamed
        reference_protos.append(
            vulnerability_pb2.Reference(
                url=url_str, type=vulnerability_pb2.Reference.Type.Value(url_type_str))) # type: ignore

    severity_protos: List[vulnerability_pb2.Severity] = [] # Renamed
    for severity_entry in self.severities: # Renamed
      severity_protos.append(
          vulnerability_pb2.Severity(
              type=vulnerability_pb2.Severity.Type.Value(severity_entry.type), # type: ignore
              score=severity_entry.score))

    credit_protos: List[vulnerability_pb2.Credit] = [] # Renamed
    for credit_item in self.credits: # Renamed
      # Ensure credit_item.type is not None before passing to Value()
      credit_type_val = None
      if credit_item.type:
          credit_type_val = vulnerability_pb2.Credit.Type.Value(credit_item.type) # type: ignore

      cr_proto = vulnerability_pb2.Credit(name=credit_item.name, contact=credit_item.contact)
      if credit_type_val is not None: # Only set if valid
          cr_proto.type = credit_type_val
      credit_protos.append(cr_proto)


    related_ids: List[str] = list(self.related) if self.related else [] # Renamed, ensure list
    alias_ids: List[str] = [] # Renamed

    # Need to handle last_modified carefully if it's updated in blocks
    final_modified_dt = self.last_modified

    if include_alias:
      # NDB fetch() is synchronous. For async, use fetch_async().
      # Assuming synchronous context here.
      related_bugs_query: ndb.Query = Bug.query(Bug.related == self.db_id) # type: ignore
      related_bugs_models: List[Bug] = related_bugs_query.fetch(projection=[Bug.db_id]) # type: ignore

      related_bug_db_ids: List[str] = [b.db_id for b in related_bugs_models if b.db_id] # type: ignore
      related_ids = sorted(list(set(related_bug_db_ids + related_ids)))

      alias_group_instance: Optional[AliasGroup] = AliasGroup.query(AliasGroup.bug_ids == self.db_id).get() # type: ignore
      if alias_group_instance:
        alias_ids = sorted(list(set(alias_group_instance.bug_ids) - {self.db_id})) # type: ignore
        if final_modified_dt and alias_group_instance.last_modified: # Ensure both dates exist
             final_modified_dt = max(final_modified_dt, alias_group_instance.last_modified)
        elif alias_group_instance.last_modified: # If original was None
             final_modified_dt = alias_group_instance.last_modified



    upstream_ids: List[str] = [] # Renamed

    if include_upstream:
      upstream_group_instance: Optional[UpstreamGroup] = UpstreamGroup.query(UpstreamGroup.db_id == self.db_id).get() # type: ignore
      if upstream_group_instance:
        upstream_ids = sorted(upstream_group_instance.upstream_ids) # type: ignore
        if final_modified_dt and upstream_group_instance.last_modified: # Ensure both dates exist
            final_modified_dt = max(final_modified_dt, upstream_group_instance.last_modified)
        elif upstream_group_instance.last_modified: # If original was None
            final_modified_dt = upstream_group_instance.last_modified

    # Re-create Timestamp if final_modified_dt changed
    if final_modified_dt and (not modified_ts or final_modified_dt != self.last_modified):
        modified_ts = timestamp_pb2.Timestamp()
        modified_ts.FromDatetime(final_modified_dt)


    result_vuln = vulnerability_pb2.Vulnerability( # Renamed
        schema_version=SCHEMA_VERSION,
        id=self.id(),
        published=published_ts,
        modified=modified_ts,  # Note the three places above where this can be set.
        aliases=alias_ids,
        related=related_ids,
        upstream=upstream_ids, # New field
        withdrawn=withdrawn_ts,
        summary=self.summary,
        details=details_str,
        affected=affected_protos,
        severity=severity_protos,
        credits=credit_protos,
        references=reference_protos)

    if self.database_specific:
      result_vuln.database_specific.update(self.database_specific)

    return result_vuln

  @ndb.tasklet
  def to_vulnerability_async(
      self,
      include_source: bool = False,
      include_alias: bool = False,
      include_upstream: bool = False) -> ndb.Future[vulnerability_pb2.Vulnerability]:
    """Converts to Vulnerability proto and retrieves aliases asynchronously."""
    # Create base vulnerability object (synchronous part)
    vuln_proto: vulnerability_pb2.Vulnerability = self.to_vulnerability(
        include_source=include_source,
        include_alias=False,  # Aliases handled async
        include_upstream=False  # Upstream handled async
    )

    # Asynchronously fetch related bug IDs
    related_bug_ids_future: ndb.Future[List[str]] = get_related_async(vuln_proto.id)
    related_bug_ids_list: List[str] = yield related_bug_ids_future
    # Combine and sort related IDs
    combined_related_ids = sorted(
        list(set(related_bug_ids_list + list(vuln_proto.related))))
    vuln_proto.related[:] = combined_related_ids # Update field in place

    # Determine initial modified time for comparison
    current_modified_time: Optional[datetime.datetime] = None
    if vuln_proto.modified.seconds or vuln_proto.modified.nanos: # Check if timestamp is set
        current_modified_time = vuln_proto.modified.ToDatetime(tz=datetime.timezone.utc)


    if include_alias:
      alias_group_future: ndb.Future[Optional[AliasGroup]] = get_aliases_async(vuln_proto.id)
      alias_group_instance: Optional[AliasGroup] = yield alias_group_future
      if alias_group_instance:
        alias_ids_list = sorted(list(set(alias_group_instance.bug_ids) - {vuln_proto.id})) # type: ignore
        vuln_proto.aliases[:] = alias_ids_list
        if alias_group_instance.last_modified:
            if current_modified_time:
                current_modified_time = max(alias_group_instance.last_modified, current_modified_time)
            else:
                current_modified_time = alias_group_instance.last_modified


    if include_upstream:
      upstream_group_future: ndb.Future[Optional[UpstreamGroup]] = get_upstream_async(vuln_proto.id)
      upstream_group_instance: Optional[UpstreamGroup] = yield upstream_group_future
      if upstream_group_instance:
        vuln_proto.upstream[:] = sorted(upstream_group_instance.upstream_ids) # type: ignore
        if upstream_group_instance.last_modified:
            if current_modified_time:
                current_modified_time = max(upstream_group_instance.last_modified, current_modified_time)
            else:
                current_modified_time = upstream_group_instance.last_modified

    # Update the modified timestamp if it changed
    if current_modified_time and (not vuln_proto.modified.seconds or vuln_proto.modified.ToDatetime(tz=datetime.timezone.utc) != current_modified_time):
        vuln_proto.modified.FromDatetime(current_modified_time)

    return vuln_proto


class RepoIndex(ndb.Model):
  """RepoIndex entry"""
  # The dependency name
  name: str = ndb.StringProperty()
  # The base cpe without the version
  base_cpe: str = ndb.StringProperty()
  # The repository commit
  commit: bytes = ndb.BlobProperty()
  # The source address
  repo_addr: str = ndb.StringProperty()
  # The scanned file extensions
  file_exts: List[str] = ndb.StringProperty(repeated=True)
  # The hash algorithm used
  file_hash_type: str = ndb.StringProperty() # TODO(ochang): Enum.
  # The repository type
  repo_type: str = ndb.StringProperty()
  # A bitmap of which buckets are empty
  empty_bucket_bitmap: bytes = ndb.BlobProperty()
  # Number of files in this repo
  file_count: int = ndb.IntegerProperty()
  # Tag name of the source
  tag: str = ndb.StringProperty()


class FileResult(ndb.Model):
  """FileResult entry containing the path and hash"""
  # The hash value of the file
  hash: bytes = ndb.BlobProperty(indexed=True)
  # The file path
  path: str = ndb.TextProperty()


class RepoIndexBucket(ndb.Model):
  """RepoIndexResult entries containing the actual hash values"""
  # The file results per file
  node_hash: bytes = ndb.BlobProperty(indexed=True)
  # number of files this hash represents
  files_contained: int = ndb.IntegerProperty()


class SourceRepositoryType(enum.IntEnum):
  """SourceRepository type."""
  GIT = 0
  BUCKET = 1
  REST_ENDPOINT = 2


class SourceRepository(ndb.Model):
  """Source repository."""
  # The SourceRepositoryType of the repository.
  type: int = ndb.IntegerProperty()
  # The name of the source.
  name: str = ndb.StringProperty()
  # The repo URL for the source for SourceRepositoryType.GIT.
  repo_url: str = ndb.StringProperty()
  # The username to use for SSH auth for SourceRepositoryType.GIT.
  repo_username: str = ndb.StringProperty()
  # Optional branch for repo for SourceRepositoryType.GIT.
  repo_branch: str = ndb.StringProperty()
  # The API endpoint for SourceRepositoryType.REST_ENDPOINT.
  rest_api_url: str = ndb.StringProperty()
  # Bucket name for SourceRepositoryType.BUCKET.
  bucket: str = ndb.StringProperty()
  # Vulnerability data not under this path is ignored by the importer.
  directory_path: str = ndb.StringProperty()
  # Last synced hash for SourceRepositoryType.GIT.
  last_synced_hash: str = ndb.StringProperty()
  # Last date recurring updates were requested.
  last_update_date: datetime.datetime = ndb.DateTimeProperty(
      tzinfo=datetime.UTC)
  # Patterns of files to exclude (regex).
  ignore_patterns: List[str] = ndb.StringProperty(repeated=True)
  # Whether this repository is editable.
  editable: bool = ndb.BooleanProperty(default=False) # TODO(ochang): Remove.
  # Default extension.
  extension: str = ndb.StringProperty(default='.yaml')
  # Key path within each file to store the vulnerability.
  key_path: str = ndb.StringProperty()
  # If true, don't analyze any Git ranges.
  ignore_git: bool = ndb.BooleanProperty(default=False)
  # Whether to detect cherypicks or not (slow for large repos).
  detect_cherrypicks: bool = ndb.BooleanProperty(default=True)
  # Whether to consider all branches when analyzing GIT ranges.
  consider_all_branches: bool = ndb.BooleanProperty(default=False)
  # Whether to populate "affected[].versions" from Git ranges.
  versions_from_repo: bool = ndb.BooleanProperty(default=True)
  # Ignore last import time once (SourceRepositoryType.BUCKET).
  ignore_last_import_time: bool = ndb.BooleanProperty(default=False)
  # HTTP link prefix to individual OSV source records.
  link: str = ndb.StringProperty()
  # HTTP link prefix to individual vulnerability records for humans.
  human_link: str = ndb.StringProperty()
  # DB prefix, if the database allocates its own.
  # https://ossf.github.io/osv-schema/#id-modified-fields
  db_prefix: List[str] = ndb.StringProperty(repeated=True)
  # Apply strict validation (JSON Schema + linter checks) to this source.
  strict_validation: bool = ndb.BooleanProperty(default=False)

  def ignore_file(self, file_path: str) -> bool:
    """Return whether or not we should be ignoring a file."""
    if not self.ignore_patterns:
      return False

    file_name = os.path.basename(file_path)
    for pattern_str in self.ignore_patterns: # Renamed
      if re.match(pattern_str, file_name):
        return True

    return False

  def _pre_put_hook(self) -> None:  # pylint: disable=arguments-differ
    """Pre-put hook for validation."""
    if self.type == SourceRepositoryType.BUCKET.value and self.editable: # Use .value for enum comparison
      raise ValueError('BUCKET SourceRepository cannot be editable.')


class AliasGroup(ndb.Model):
  """Alias group."""
  bug_ids: List[str] = ndb.StringProperty(repeated=True)
  last_modified: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.timezone.utc) # tz aware


class AliasAllowListEntry(ndb.Model):
  """Alias group allow list entry."""
  bug_id: str = ndb.StringProperty()


class AliasDenyListEntry(ndb.Model):
  """Alias group deny list entry."""
  bug_id: str = ndb.StringProperty()


class UpstreamGroup(ndb.Model):
  """Upstream group for storing transitive upstreams of a Bug
     This group is in a separate table in order to prevent additional race
     conditions. This makes sure that only the worker is modifying the Bug
     entity directly. 
  """
  # Database ID of the corresponding Bug
  db_id: str = ndb.StringProperty()
  # List of transitive upstreams
  upstream_ids: List[str] = ndb.StringProperty(repeated=True)
  upstream_hierarchy: Dict[str, Any] = ndb.JsonProperty() # Assuming JSON object
  # Date when group was last modified
  last_modified: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.timezone.utc) # tz aware


# TODO(gongh@): redesign this to make it easy to scale.
class ImportFindings(enum.IntEnum):
  """The possible quality findings about an individual record."""
  UNKNOWN = -1
  NONE = 0
  DELETED = 1
  INVALID_JSON = 2
  INVALID_PACKAGE = 3
  INVALID_PURL = 4
  INVALID_VERSION = 5
  INVALID_COMMIT = 6
  INVALID_RANGE = 7
  INVALID_RECORD = 8
  INVALID_ALIASES = 9
  INVALID_UPSTREAM = 10
  INVALID_RELATED = 11
  BAD_ALIASED_CVE = 12


class ImportFinding(ndb.Model):
  """Quality findings about an individual record."""
  bug_id: str = ndb.StringProperty()
  source: str = ndb.StringProperty()
  findings: List[ImportFindings] = ndb.IntegerProperty(repeated=True) # type: ignore[assignment]
  first_seen: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.timezone.utc) # tz aware
  last_attempt: datetime.datetime = ndb.DateTimeProperty(tzinfo=datetime.timezone.utc) # tz aware

  def _pre_put_hook(self) -> None:  # pylint: disable=arguments-differ
    """Pre-put hook for setting key."""
    if not self.key:  # pylint: disable=access-member-before-definition
      self.key = ndb.Key(ImportFinding, self.bug_id) # type: ignore[type-arg]

  def to_proto(self) -> importfinding_pb2.ImportFinding:
    """Converts to ImportFinding proto."""
    # Ensure first_seen and last_attempt are not None before calling timestamp_pb()
    first_seen_ts = None
    if self.first_seen:
        first_seen_ts = timestamp_pb2.Timestamp()
        first_seen_ts.FromDatetime(self.first_seen)

    last_attempt_ts = None
    if self.last_attempt:
        last_attempt_ts = timestamp_pb2.Timestamp()
        last_attempt_ts.FromDatetime(self.last_attempt)

    return importfinding_pb2.ImportFinding(
        bug_id=self.bug_id,
        source=self.source,
        findings=self.findings, # Assuming findings is List[int] compatible with proto
        first_seen=first_seen_ts,
        last_attempt=last_attempt_ts,
    )


def get_source_repository(source_name: str) -> Optional[SourceRepository]:
  """Get source repository."""
  return SourceRepository.get_by_id(source_name) # type: ignore[no-any-return]


def sorted_events(ecosystem_name: Optional[str], range_type_str: str, # Renamed
                  events_list: List[AffectedEvent]) -> List[AffectedEvent]:
  """Sort events."""
  if range_type_str == 'GIT':
    # No need to sort.
    return events_list

  ecosystem_helper_instance: Optional[ecosystems.Ecosystem] = None # Renamed
  if range_type_str == 'SEMVER':
    ecosystem_helper_instance = ecosystems.SemverEcosystem()
  elif ecosystem_name: # Ensure ecosystem_name is not None
    ecosystem_helper_instance = ecosystems.get(ecosystem_name)

  if ecosystem_helper_instance is None or not ecosystem_helper_instance.supports_ordering:
    # Include ecosystem_name in error if available
    eco_str = ecosystem_name or "Unknown"
    raise ValueError(f'Unsupported ecosystem {eco_str} for sorting events of type {range_type_str}')


  # Remove any magic '0' values.
  sorted_copy_list: List[AffectedEvent] = [] # Renamed
  zero_event_item: Optional[AffectedEvent] = None # Renamed
  for event_item in events_list: # Renamed
    if event_item.value == '0':
      zero_event_item = event_item
      continue

    sorted_copy_list.append(event_item)

  # Ensure ecosystem_helper_instance is not None before calling sort_key
  # This should be guaranteed by the check above, but for type safety:
  if ecosystem_helper_instance:
      sorted_copy_list.sort(key=lambda e: ecosystem_helper_instance.sort_key(e.value)) # type: ignore

  if zero_event_item:
    sorted_copy_list.insert(0, zero_event_item)

  return sorted_copy_list


@ndb.tasklet
def get_aliases_async(bug_id: str) -> ndb.Future[Optional[AliasGroup]]:
  """Gets aliases asynchronously."""
  alias_group_future = AliasGroup.query(AliasGroup.bug_ids == bug_id).get_async() # type: ignore[attr-defined]
  alias_group_result: Optional[AliasGroup] = yield alias_group_future
  return alias_group_result


@ndb.tasklet
def get_related_async(bug_id: str) -> ndb.Future[List[str]]:
  """Gets related bugs asynchronously."""
  # NDB queries with projection return dictionaries, not full model instances,
  # unless configured otherwise. Assuming Bug.db_id is projected.
  # The fetch_async method returns a Future whose result is a list of these projected entities.
  related_bugs_future: ndb.Future[List[Bug]] = Bug.query(Bug.related == bug_id).fetch_async(projection=[Bug.db_id]) # type: ignore[attr-defined]
  related_bugs_list: List[Bug] = yield related_bugs_future
  # Ensure db_id is not None for each bug in the list
  related_bug_ids_list: List[str] = [bug.db_id for bug in related_bugs_list if bug.db_id]
  return related_bug_ids_list


@ndb.tasklet
def get_upstream_async(bug_id: str) -> ndb.Future[Optional[UpstreamGroup]]:
  """Gets upstream bugs asynchronously."""
  upstream_group_future = UpstreamGroup.query(UpstreamGroup.db_id == bug_id).get_async() # type: ignore[attr-defined]
  upstream_group_result: Optional[UpstreamGroup] = yield upstream_group_future
  return upstream_group_result
