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
import re
import os

from google.cloud import ndb
from google.protobuf import json_format
from google.protobuf import timestamp_pb2

# pylint: disable=relative-beyond-top-level
from . import bug
from . import ecosystems
from . import purl_helpers
from . import semver_index
from . import sources
from . import vulnerability_pb2

SCHEMA_VERSION = '1.2.0'


def _check_valid_severity(prop, value):
  """Check valid severity."""
  del prop

  if value not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
    raise ValueError('Invalid severity: ' + value)


def _check_valid_range_type(prop, value):
  """Check valid range type."""
  del prop

  if value not in ('GIT', 'SEMVER', 'ECOSYSTEM'):
    raise ValueError('Invalid range type: ' + value)


def _check_valid_event_type(prop, value):
  """Check valid event type."""
  del prop

  if value not in ('introduced', 'fixed', 'limit'):
    raise ValueError('Invalid event type: ' + value)


def utcnow():
  """For mocking."""
  return datetime.datetime.utcnow()


class IDCounter(ndb.Model):
  """Counter for ID allocations."""
  # Next ID to allocate.
  next_id = ndb.IntegerProperty()


class AffectedCommit(ndb.Model):
  """AffectedCommit entry."""
  # The main bug ID.
  bug_id = ndb.StringProperty()
  # The commit hash.
  commit = ndb.StringProperty()
  # Project for the bug.
  project = ndb.StringProperty()
  # Ecosystem for the affected commit.
  ecosystem = ndb.StringProperty()
  # Whether or not the bug is public.
  public = ndb.BooleanProperty()


class RegressResult(ndb.Model):
  """Regression results."""
  # The commit hash.
  commit = ndb.StringProperty(default='')
  # Vulnerability summary.
  summary = ndb.TextProperty()
  # Vulnerability details.
  details = ndb.TextProperty()
  # Error (if any).
  error = ndb.StringProperty()
  # OSS-Fuzz issue ID.
  issue_id = ndb.StringProperty()
  # Project for the bug.
  project = ndb.StringProperty()
  # Package ecosystem for the project.
  ecosystem = ndb.StringProperty()
  # Repo URL.
  repo_url = ndb.StringProperty()
  # Severity of the bug.
  severity = ndb.StringProperty(validator=_check_valid_severity)
  # Reference URLs.
  reference_urls = ndb.StringProperty(repeated=True)
  # Source timestamp.
  timestamp = ndb.DateTimeProperty()


class FixResult(ndb.Model):
  """Fix results."""
  # The commit hash.
  commit = ndb.StringProperty(default='')
  # Vulnerability summary.
  summary = ndb.TextProperty()
  # Vulnerability details.
  details = ndb.TextProperty()
  # Error (if any).
  error = ndb.StringProperty()
  # OSS-Fuzz issue ID.
  issue_id = ndb.StringProperty()
  # Project for the bug.
  project = ndb.StringProperty()
  # Package ecosystem for the project.
  ecosystem = ndb.StringProperty()
  # Repo URL.
  repo_url = ndb.StringProperty()
  # Severity of the bug.
  severity = ndb.StringProperty(validator=_check_valid_severity)
  # Reference URLs.
  reference_urls = ndb.StringProperty(repeated=True)
  # Source timestamp.
  timestamp = ndb.DateTimeProperty()


class AffectedRange(ndb.Model):
  """Affected range."""
  # Type of range.
  type = ndb.StringProperty(validator=_check_valid_range_type)
  # Repo URL.
  repo_url = ndb.StringProperty()
  # The regressing commit.
  introduced = ndb.StringProperty()
  # The fix commit.
  fixed = ndb.StringProperty()


class AffectedEvent(ndb.Model):
  """Affected event."""
  type = ndb.StringProperty(validator=_check_valid_event_type)
  value = ndb.StringProperty()


class AffectedRange2(ndb.Model):
  """Affected range."""
  # Type of range.
  type = ndb.StringProperty(validator=_check_valid_range_type)
  # Repo URL.
  repo_url = ndb.StringProperty()
  # Events.
  events = ndb.LocalStructuredProperty(AffectedEvent, repeated=True)


class SourceOfTruth(enum.IntEnum):
  """Source of truth."""
  NONE = 0
  # Internal to OSV (e.g. private OSS-Fuzz bugs).
  INTERNAL = 1
  # Vulnerabilities that are available in a public repo.
  SOURCE_REPO = 2


class Package(ndb.Model):
  """Package."""
  ecosystem = ndb.StringProperty()
  name = ndb.StringProperty()
  purl = ndb.StringProperty()


class AffectedPackage(ndb.Model):
  """Affected packages."""
  # The affected package identifier.
  package = ndb.StructuredProperty(Package)
  # The list of affected ranges.
  ranges = ndb.LocalStructuredProperty(AffectedRange2, repeated=True)
  # The list of explicit affected versions.
  versions = ndb.TextProperty(repeated=True)
  # Database specific metadata.
  database_specific = ndb.JsonProperty()
  # Ecosystem specific metadata.
  ecosystem_specific = ndb.JsonProperty()


class Credit(ndb.Model):
  """Credits."""
  name = ndb.StringProperty()
  contact = ndb.StringProperty(repeated=True)


class Severity(ndb.Model):
  """Severity."""
  type = ndb.StringProperty()
  score = ndb.StringProperty()


class Bug(ndb.Model):
  """Bug entity."""
  OSV_ID_PREFIX = 'OSV-'
  # Very large fake version to use when there is no fix available.
  _NOT_FIXED_SEMVER = '999999.999999.999999'

  # Display ID as used by the source database. The full qualified database that
  # OSV tracks this as may be different.
  db_id = ndb.StringProperty()
  # Other IDs this bug is known as.
  aliases = ndb.StringProperty(repeated=True)
  # Related IDs.
  related = ndb.StringProperty(repeated=True)
  # Status of the bug.
  status = ndb.IntegerProperty()
  # Timestamp when Bug was allocated.
  timestamp = ndb.DateTimeProperty()
  # When the entry was last edited.
  last_modified = ndb.DateTimeProperty()
  # When the entry was withdrawn.
  withdrawn = ndb.DateTimeProperty()
  # The source identifier.
  # For OSS-Fuzz, this oss-fuzz:<ClusterFuzz testcase ID>.
  # For others this is <source>:<path/to/source>.
  source_id = ndb.StringProperty()
  # The main fixed commit (from bisection).
  fixed = ndb.StringProperty(default='')
  # The main regressing commit (from bisection).
  regressed = ndb.StringProperty(default='')
  # All affected ranges. TODO(ochang): To be removed.
  affected_ranges = ndb.StructuredProperty(AffectedRange, repeated=True)
  # List of affected versions.
  affected = ndb.TextProperty(repeated=True)
  # List of normalized versions indexed for fuzzy matching.
  affected_fuzzy = ndb.StringProperty(repeated=True)
  # OSS-Fuzz issue ID.
  issue_id = ndb.StringProperty()
  # Package URL for this package.
  purl = ndb.StringProperty(repeated=True)
  # Project/package name for the bug.
  project = ndb.StringProperty(repeated=True)
  # Package ecosystem for the project.
  ecosystem = ndb.StringProperty(repeated=True)
  # Summary for the bug.
  summary = ndb.TextProperty()
  # Vulnerability details.
  details = ndb.TextProperty()
  # Severity of the bug.
  severities = ndb.LocalStructuredProperty(Severity, repeated=True)
  # Credits for the bug.
  credits = ndb.LocalStructuredProperty(Credit, repeated=True)
  # Whether or not the bug is public (OSS-Fuzz only).
  public = ndb.BooleanProperty()
  # Reference URL types (dict of url -> type).
  reference_url_types = ndb.JsonProperty()
  # Search indices (auto-populated)
  search_indices = ndb.StringProperty(repeated=True)
  # Whether or not the bug has any affected versions (auto-populated).
  has_affected = ndb.BooleanProperty()
  # Source of truth for this Bug.
  source_of_truth = ndb.IntegerProperty(default=SourceOfTruth.INTERNAL)
  # Whether the bug is fixed (indexed for querying).
  is_fixed = ndb.BooleanProperty()
  # Database specific.
  database_specific = ndb.JsonProperty()
  # Normalized SEMVER fixed indexes for querying.
  semver_fixed_indexes = ndb.StringProperty(repeated=True)
  # Affected packages and versions.
  affected_packages = ndb.LocalStructuredProperty(
      AffectedPackage, repeated=True)
  # The source of this Bug.
  source = ndb.StringProperty()

  def id(self):
    """Get the bug ID."""
    if self.db_id:
      return self.db_id

    # TODO(ochang): Remove once all existing bugs have IDs migrated.
    if re.match(r'^\d+', self.key.id()):
      return self.OSV_ID_PREFIX + self.key.id()

    return self.key.id()

  @property
  def repo_url(self):
    """Repo URL."""
    for affected_package in self.affected_packages:
      for affected_range in affected_package.ranges:
        if affected_range.repo_url:
          return affected_range.repo_url

    return None

  @classmethod
  def get_by_id(cls, vuln_id, *args, **kwargs):
    """Overridden get_by_id to handle OSV allocated IDs."""
    result = cls.query(cls.db_id == vuln_id).get()
    if result:
      return result

    # TODO(ochang): Remove once all exsting bugs have IDs migrated.
    if vuln_id.startswith(cls.OSV_ID_PREFIX):
      vuln_id = vuln_id[len(cls.OSV_ID_PREFIX):]

    return super().get_by_id(vuln_id, *args, **kwargs)

  def _tokenize(self, value):
    """Tokenize value for indexing."""
    if not value:
      return []

    value_lower = value.lower()
    return re.split(r'\W+', value_lower) + [value_lower]

  def _pre_put_hook(self):
    """Pre-put hook for populating search indices."""
    search_indices = set()

    search_indices.update(self._tokenize(self.id()))

    for affected_package in self.affected_packages:
      # Set PURL if it wasn't provided.
      if not affected_package.package.purl:
        affected_package.package.purl = purl_helpers.package_to_purl(
            affected_package.package.ecosystem, affected_package.package.name)

    self.project = list({
        pkg.package.name for pkg in self.affected_packages if pkg.package.name
    })
    self.project.sort()

    self.ecosystem = list({
        pkg.package.ecosystem
        for pkg in self.affected_packages
        if pkg.package.ecosystem
    })
    self.ecosystem.sort()

    self.purl = list({
        pkg.package.purl for pkg in self.affected_packages if pkg.package.purl
    })
    self.purl.sort()

    for project in self.project:
      search_indices.update(self._tokenize(project))

    for ecosystem in self.ecosystem:
      search_indices.update(self._tokenize(ecosystem))

    for alias in self.aliases:
      search_indices.update(self._tokenize(alias))

    self.search_indices = list(set(search_indices))
    self.search_indices.sort()

    self.affected_fuzzy = []
    self.semver_fixed_indexes = []
    self.has_affected = False
    self.is_fixed = False

    for affected_package in self.affected_packages:
      # Indexes used for querying by exact version.
      if ecosystems.get(affected_package.package.ecosystem):
        # No need to normalize if the ecosystem is supported.
        self.affected_fuzzy.extend(affected_package.versions)
      else:
        self.affected_fuzzy.extend(
            bug.normalize_tags(affected_package.versions))

      self.has_affected |= bool(affected_package.versions)

      for affected_range in affected_package.ranges:
        fixed_version = None
        for event in affected_range.events:
          # Index used to query by fixed/unfixed.
          if event.type == 'fixed':
            self.is_fixed = True
            fixed_version = event.value

        if affected_range.type == 'SEMVER':
          # Indexes used for querying by semver.
          fixed = fixed_version or self._NOT_FIXED_SEMVER
          self.semver_fixed_indexes.append(semver_index.normalize(fixed))

        self.has_affected |= (affected_range.type in ('SEMVER', 'ECOSYSTEM'))

    self.affected_fuzzy = list(set(self.affected_fuzzy))
    self.affected_fuzzy.sort()

    if not self.last_modified:
      self.last_modified = utcnow()

    if self.source_id:
      self.source, _ = sources.parse_source_id(self.source_id)

    if not self.source:
      raise ValueError('Source not specified for Bug.')

    if not self.db_id:
      raise ValueError('DB ID not specified for Bug.')

    if not self.key:  # pylint: disable=access-member-before-definition
      source_repo = get_source_repository(self.source)
      if not source_repo:
        raise ValueError(f'Invalid source {self.source}')

      if source_repo.db_prefix and self.db_id.startswith(source_repo.db_prefix):
        key_id = self.db_id
      else:
        key_id = f'{self.source}:{self.db_id}'

      self.key = ndb.Key(Bug, key_id)

    if self.withdrawn:
      self.status = bug.BugStatus.INVALID

  def update_from_vulnerability(self, vulnerability):
    """Set fields from vulnerability. Does not set the ID."""
    self.summary = vulnerability.summary
    self.details = vulnerability.details
    self.reference_url_types = {
        ref.url: vulnerability_pb2.Reference.Type.Name(ref.type)
        for ref in vulnerability.references
    }

    if vulnerability.HasField('modified'):
      self.last_modified = vulnerability.modified.ToDatetime()
    if vulnerability.HasField('published'):
      self.timestamp = vulnerability.published.ToDatetime()
    if vulnerability.HasField('withdrawn'):
      self.withdrawn = vulnerability.withdrawn.ToDatetime()
    else:
      self.withdrawn = None

    self.aliases = list(vulnerability.aliases)
    self.related = list(vulnerability.related)

    self.affected_packages = []
    for affected_package in vulnerability.affected:
      current = AffectedPackage()
      current.package = Package(
          name=affected_package.package.name,
          ecosystem=affected_package.package.ecosystem,
          purl=affected_package.package.purl)
      current.ranges = []

      for affected_range in affected_package.ranges:
        current_range = AffectedRange2(
            type=vulnerability_pb2.Range.Type.Name(affected_range.type),
            repo_url=affected_range.repo,
            events=[])

        for evt in affected_range.events:
          if evt.introduced:
            current_range.events.append(
                AffectedEvent(type='introduced', value=evt.introduced))
            continue

          if evt.fixed:
            current_range.events.append(
                AffectedEvent(type='fixed', value=evt.fixed))
            continue

          if evt.limit:
            current_range.events.append(
                AffectedEvent(type='limit', value=evt.limit))
            continue

        current.ranges.append(current_range)

      current.versions = list(affected_package.versions)
      if affected_package.database_specific:
        current.database_specific = json_format.MessageToDict(
            affected_package.database_specific,
            preserving_proto_field_name=True)

      if affected_package.ecosystem_specific:
        current.ecosystem_specific = json_format.MessageToDict(
            affected_package.ecosystem_specific,
            preserving_proto_field_name=True)

      self.affected_packages.append(current)

    self.severities = []
    for severity in vulnerability.severity:
      self.severities.append(
          Severity(
              type=vulnerability_pb2.Severity.Type.Name(severity.type),
              score=severity.score))

    self.credits = []
    for credit in vulnerability.credits:
      self.credits.append(
          Credit(name=credit.name, contact=list(credit.contact)))

    if vulnerability.database_specific:
      self.database_specific = json_format.MessageToDict(
          vulnerability.database_specific, preserving_proto_field_name=True)

  def to_vulnerability(self, include_source=False):
    """Convert to Vulnerability proto."""
    package = None
    affected = []

    source_link = None
    if self.source and include_source:
      source_repo = get_source_repository(self.source)
      if source_repo and source_repo.link:
        source_link = source_repo.link + sources.source_path(source_repo, self)

    if self.affected_packages:
      for affected_package in self.affected_packages:
        ranges = []
        for affected_range in affected_package.ranges:
          events = []
          for event in affected_range.events:
            kwargs = {event.type: event.value}
            events.append(vulnerability_pb2.Event(**kwargs))

          current_range = vulnerability_pb2.Range(
              type=vulnerability_pb2.Range.Type.Value(affected_range.type),
              repo=affected_range.repo_url,
              events=events)

          ranges.append(current_range)

        current = vulnerability_pb2.Affected(
            package=vulnerability_pb2.Package(
                name=affected_package.package.name,
                ecosystem=affected_package.package.ecosystem,
                purl=affected_package.package.purl),
            ranges=ranges,
            versions=affected_package.versions)

        if affected_package.database_specific:
          current.database_specific.update(affected_package.database_specific)

        if source_link:
          current.database_specific.update({'source': source_link})

        if affected_package.ecosystem_specific:
          current.ecosystem_specific.update(affected_package.ecosystem_specific)

        affected.append(current)

    details = self.details

    if self.last_modified:
      modified = timestamp_pb2.Timestamp()
      modified.FromDatetime(self.last_modified)
    else:
      modified = None

    if self.withdrawn:
      withdrawn = timestamp_pb2.Timestamp()
      withdrawn.FromDatetime(self.withdrawn)
    else:
      withdrawn = None

    published = timestamp_pb2.Timestamp()
    published.FromDatetime(self.timestamp)

    references = []
    if self.reference_url_types:
      for url, url_type in self.reference_url_types.items():
        references.append(
            vulnerability_pb2.Reference(
                url=url, type=vulnerability_pb2.Reference.Type.Value(url_type)))

    severity = []
    for entry in self.severities:
      severity.append(
          vulnerability_pb2.Severity(
              type=vulnerability_pb2.Severity.Type.Value(entry.type),
              score=entry.score))

    credits_ = []
    for credit in self.credits:
      credits_.append(
          vulnerability_pb2.Credit(name=credit.name, contact=credit.contact))

    result = vulnerability_pb2.Vulnerability(
        schema_version=SCHEMA_VERSION,
        id=self.id(),
        published=published,
        modified=modified,
        aliases=self.aliases,
        related=self.related,
        withdrawn=withdrawn,
        summary=self.summary,
        details=details,
        package=package,
        affected=affected,
        severity=severity,
        credits=credits_,
        references=references)

    if self.database_specific:
      result.database_specific.update(self.database_specific)

    return result


class SourceRepositoryType(enum.IntEnum):
  """SourceRepository type."""
  GIT = 0
  BUCKET = 1


class SourceRepository(ndb.Model):
  """Source repository."""
  # The type of the repository.
  type = ndb.IntegerProperty()
  # The name of the source.
  name = ndb.StringProperty()
  # The repo URL for the source.
  repo_url = ndb.StringProperty()
  # The username to use for SSH auth.
  repo_username = ndb.StringProperty()
  # Optional branch for repo.
  repo_branch = ndb.StringProperty()
  # Bucket name.
  bucket = ndb.StringProperty()
  # The directory in the repo where Vulnerability data is stored.
  directory_path = ndb.StringProperty()
  # Last synced hash.
  last_synced_hash = ndb.StringProperty()
  # Last date recurring updates were requested.
  last_update_date = ndb.DateProperty()
  # Patterns of files to exclude (regex).
  ignore_patterns = ndb.StringProperty(repeated=True)
  # Whether this repository is editable.
  editable = ndb.BooleanProperty(default=False)
  # Default extension.
  extension = ndb.StringProperty(default='.yaml')
  # Key path within each file to store the vulnerability.
  key_path = ndb.StringProperty()
  # It true, don't analyze any git ranges.
  ignore_git = ndb.BooleanProperty(default=False)
  # Whether to detect cherypicks or not (slow for large repos).
  detect_cherrypicks = ndb.BooleanProperty(default=True)
  # Whether to populate "versions" from git ranges.
  versions_from_repo = ndb.BooleanProperty(default=True)
  # HTTP link prefix.
  link = ndb.StringProperty()
  # DB prefix, if the database allocates its own.
  db_prefix = ndb.StringProperty()

  def ignore_file(self, file_path):
    """Return whether or not we should be ignoring a file."""
    if not self.ignore_patterns:
      return False

    file_name = os.path.basename(file_path)
    for pattern in self.ignore_patterns:
      if re.match(pattern, file_name):
        return True

    return False

  def _pre_put_hook(self):
    """Pre-put hook for validation."""
    if self.type == SourceRepositoryType.BUCKET and self.editable:
      raise ValueError('BUCKET SourceRepository cannot be editable.')


def get_source_repository(source_name):
  """Get source repository."""
  return SourceRepository.get_by_id(source_name)


def sorted_events(ecosystem, range_type, events):
  """Sort events."""
  if range_type == 'GIT':
    # No need to sort.
    return events

  if range_type == 'SEMVER':
    ecosystem_helper = ecosystems.SemverEcosystem()
  else:
    ecosystem_helper = ecosystems.get(ecosystem)

  if ecosystem_helper is None:
    raise ValueError('Unsupported ecosystem ' + ecosystem)

  # Remove any magic '0' values.
  sorted_copy = []
  zero_event = None
  for event in events:
    if event.value == '0':
      zero_event = event
      continue

    sorted_copy.append(event)

  sorted_copy.sort(key=lambda e: ecosystem_helper.sort_key(e.value))
  if zero_event:
    sorted_copy.insert(0, zero_event)

  return sorted_copy
