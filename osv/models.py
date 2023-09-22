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

from urllib.parse import urlparse
from typing import List

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

SCHEMA_VERSION = '1.6.0'


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

  if value not in ('introduced', 'fixed', 'last_affected', 'limit'):
    raise ValueError('Invalid event type: ' + value)


def utcnow():
  """For mocking."""
  return datetime.datetime.utcnow()


def _get_purl_indexes(affected_packages):
  """Get list of purls from affected packages, with and without qualifiers"""
  resulting_set = set()
  for pkg in affected_packages:
    if pkg.package.purl:
      resulting_set.add(pkg.package.purl)
      if '?' in pkg.package.purl:
        resulting_set.add(pkg.package.purl.split('?')[0])
  return list(resulting_set)


def _repo_name(repo_url: str) -> str:
  # https://github.com/eclipse-openj9/openj9 -> openj9
  url = urlparse(repo_url)
  assumed_reponame = os.path.dirname(url.path).lstrip("/")
  name = assumed_reponame.rstrip(".git")
  return name


def _maybe_strip_repo_prefixes(versions: List[str],
                               repo_urls: List[str]) -> str:
  """Try to strip the repo name from tags prior to normalizing.

  There are some particularly regex-unfriendly tag names that prefix the
  reponame that end in a number, like "openj9-0.8.0", resulting in an
  incorrectly normalized version.
  """

  repo_stripped_versions = versions

  for repo_url in repo_urls:
    assumed_reponame = _repo_name(repo_url).lower()
    repo_stripped_versions = [
        v.lstrip(assumed_reponame).lstrip("-") for v in versions
    ]

  return repo_stripped_versions


class IDCounter(ndb.Model):
  """Counter for ID allocations."""
  # Next ID to allocate.
  next_id = ndb.IntegerProperty()


class AffectedCommits(ndb.Model):
  """AffectedCommits entry."""
  MAX_COMMITS_PER_ENTITY = 10000

  # The main bug ID.
  bug_id = ndb.StringProperty()
  # The commit hash.
  commits = ndb.BlobProperty(repeated=True, indexed=True)
  # Whether or not the bug is public.
  public = ndb.BooleanProperty()
  # The page for this batch of commits.
  page = ndb.IntegerProperty(indexed=False)


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


class Severity(ndb.Model):
  """Severity."""
  type = ndb.StringProperty()
  score = ndb.StringProperty()


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
  # Severity of the bug.
  severities = ndb.LocalStructuredProperty(Severity, repeated=True)


class Credit(ndb.Model):
  """Credits."""
  name = ndb.StringProperty()
  contact = ndb.StringProperty(repeated=True)
  type = ndb.StringProperty()


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
  # Last modified field of the original imported file
  import_last_modified = ndb.DateTimeProperty()
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

  def _pre_put_hook(self):  # pylint: disable=arguments-differ
    """Pre-put hook for populating search indices."""
    search_indices = set()

    search_indices.update(self._tokenize(self.id()))

    for pkg in self.affected_packages:
      # Set PURL if it wasn't provided.
      if not pkg.package.purl:
        pkg.package.purl = purl_helpers.package_to_purl(
            ecosystems.normalize(pkg.package.ecosystem), pkg.package.name)

    self.project = list({
        pkg.package.name for pkg in self.affected_packages if pkg.package.name
    })
    self.project.sort()

    ecosystems_set = {
        pkg.package.ecosystem
        for pkg in self.affected_packages
        if pkg.package.ecosystem
    }

    # For all ecosystems that specify a specific version with colon,
    # also add the base name
    ecosystems_set.update({ecosystems.normalize(x) for x in ecosystems_set})

    self.ecosystem = list(ecosystems_set)
    self.ecosystem.sort()

    self.purl = _get_purl_indexes(self.affected_packages)
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
      ecosystem_helper = ecosystems.get(affected_package.package.ecosystem)
      if ecosystem_helper and ecosystem_helper.supports_ordering:
        # No need to normalize if the ecosystem is supported.
        self.affected_fuzzy.extend(affected_package.versions)
      else:
        self.affected_fuzzy.extend(
            bug.normalize_tags(
                _maybe_strip_repo_prefixes(
                    affected_package.versions,
                    [range.repo_url for range in affected_package.ranges])))

      self.has_affected |= bool(affected_package.versions)

      for affected_range in affected_package.ranges:
        fixed_version = None
        for event in affected_range.events:
          # Index used to query by fixed/unfixed.
          if event.type == 'limit':
            self.is_fixed = True
            fixed_version = event.value

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

          if evt.last_affected:
            current_range.events.append(
                AffectedEvent(type='last_affected', value=evt.last_affected))
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

      current.severities = []
      for severity in affected_package.severity:
        current.severities.append(
            Severity(
                type=vulnerability_pb2.Severity.Type.Name(severity.type),
                score=severity.score))

      self.affected_packages.append(current)

    self.severities = []
    for severity in vulnerability.severity:
      self.severities.append(
          Severity(
              type=vulnerability_pb2.Severity.Type.Name(severity.type),
              score=severity.score))

    self.credits = []
    for credit in vulnerability.credits:
      cr = Credit(name=credit.name, contact=list(credit.contact))
      if credit.type:
        cr.type = vulnerability_pb2.Credit.Type.Name(credit.type)
      self.credits.append(cr)

    if vulnerability.database_specific:
      self.database_specific = json_format.MessageToDict(
          vulnerability.database_specific, preserving_proto_field_name=True)

  def to_vulnerability_minimal(self):
    """Convert to Vulnerability proto (minimal)."""
    if self.last_modified:
      modified = timestamp_pb2.Timestamp()
      modified.FromDatetime(self.last_modified)
    else:
      modified = None

    return vulnerability_pb2.Vulnerability(id=self.id(), modified=modified)

  def to_vulnerability(self, include_source=False):
    """Convert to Vulnerability proto."""
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

        # Converted CVE records have no package defined.
        # Avoid exporting an empty package field.
        if not current.package.ListFields():
          current.ClearField("package")

        if affected_package.database_specific:
          current.database_specific.update(affected_package.database_specific)

        if source_link:
          current.database_specific.update({'source': source_link})

        if affected_package.ecosystem_specific:
          current.ecosystem_specific.update(affected_package.ecosystem_specific)

        for entry in affected_package.severities:
          current.severity.append(
              vulnerability_pb2.Severity(
                  type=vulnerability_pb2.Severity.Type.Value(entry.type),
                  score=entry.score))

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
      cr = vulnerability_pb2.Credit(name=credit.name, contact=credit.contact)
      if credit.type:
        cr.type = vulnerability_pb2.Credit.Type.Value(credit.type)
      credits_.append(cr)

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
        affected=affected,
        severity=severity,
        credits=credits_,
        references=references)

    if self.database_specific:
      result.database_specific.update(self.database_specific)

    return result


class RepoIndex(ndb.Model):
  """RepoIndex entry"""
  # The dependency name
  name = ndb.StringProperty()
  # The base cpe without the version
  base_cpe = ndb.StringProperty()
  # The repository commit
  commit = ndb.BlobProperty()
  # The source address
  repo_addr = ndb.StringProperty()
  # The scanned file extensions
  file_exts = ndb.StringProperty(repeated=True)
  # The hash algorithm used
  file_hash_type = ndb.StringProperty()
  # The repository type
  repo_type = ndb.StringProperty()
  # A bitmap of which buckets are empty
  empty_bucket_bitmap = ndb.BlobProperty()
  # Number of files in this repo
  file_count = ndb.IntegerProperty()
  # Tag name of the source
  tag = ndb.StringProperty()


class FileResult(ndb.Model):
  """FileResult entry containing the path and hash"""
  # The hash value of the file
  hash = ndb.BlobProperty(indexed=True)
  # The file path
  path = ndb.TextProperty()


class RepoIndexBucket(ndb.Model):
  """RepoIndexResult entries containing the actual hash values"""
  # The file results per file
  node_hash = ndb.BlobProperty(indexed=True)
  # number of files this hash represents
  files_contained = ndb.IntegerProperty()


class SourceRepositoryType(enum.IntEnum):
  """SourceRepository type."""
  GIT = 0
  BUCKET = 1


class SourceRepository(ndb.Model):
  """Source repository."""
  # The SourceRepositoryType of the repository.
  type = ndb.IntegerProperty()
  # The name of the source.
  name = ndb.StringProperty()
  # The repo URL for the source for SourceRepositoryType.GIT.
  repo_url = ndb.StringProperty()
  # The username to use for SSH auth for SourceRepositoryType.GIT.
  repo_username = ndb.StringProperty()
  # Optional branch for repo for SourceRepositoryType.GIT.
  repo_branch = ndb.StringProperty()
  # Bucket name for SourceRepositoryType.BUCKET.
  bucket = ndb.StringProperty()
  # Vulnerability data not under this path is ignored by the importer.
  directory_path = ndb.StringProperty()
  # Last synced hash for SourceRepositoryType.GIT.
  last_synced_hash = ndb.StringProperty()
  # Last date recurring updates were requested.
  last_update_date = ndb.DateTimeProperty()
  # Patterns of files to exclude (regex).
  ignore_patterns = ndb.StringProperty(repeated=True)
  # Whether this repository is editable.
  editable = ndb.BooleanProperty(default=False)
  # Default extension.
  extension = ndb.StringProperty(default='.yaml')
  # Key path within each file to store the vulnerability.
  key_path = ndb.StringProperty()
  # It true, don't analyze any Git ranges.
  ignore_git = ndb.BooleanProperty(default=False)
  # Whether to detect cherypicks or not (slow for large repos).
  detect_cherrypicks = ndb.BooleanProperty(default=True)
  # Whether to populate "affected[].versions" from Git ranges.
  versions_from_repo = ndb.BooleanProperty(default=True)
  # Ignore last import time once (SourceRepositoryType.BUCKET).
  ignore_last_import_time = ndb.BooleanProperty(default=False)
  # HTTP link prefix to individual OSV source records.
  link = ndb.StringProperty()
  # HTTP link prefix to individual vulnerability records for humans.
  human_link = ndb.StringProperty()
  # DB prefix, if the database allocates its own.
  # https://ossf.github.io/osv-schema/#id-modified-fields
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

  def _pre_put_hook(self):  # pylint: disable=arguments-differ
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

  if ecosystem_helper is None or not ecosystem_helper.supports_ordering:
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
