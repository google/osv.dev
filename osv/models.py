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

from datetime import datetime
import enum
import logging
import re
import os

from urllib.parse import urlparse
from typing import Self

from google.cloud import ndb
from google.protobuf import json_format
from google.protobuf import timestamp_pb2
from osv import importfinding_pb2

# pylint: disable=relative-beyond-top-level
from . import bug
from . import ecosystems
from . import purl_helpers
from . import semver_index
from . import sources
from . import vulnerability_pb2

SCHEMA_VERSION = '1.6.0'

_MAX_GIT_VERSIONS_TO_INDEX = 5000


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
  # The alternative mentioned in the deprecation notice
  # does not behave in the same way? Tests fail.
  return datetime.utcnow()


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


def _maybe_strip_repo_prefixes(versions: list[str],
                               repo_urls: list[str]) -> str:
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
  timestamp: datetime = ndb.DateTimeProperty()


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
  timestamp: datetime = ndb.DateTimeProperty()


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
  timestamp: datetime = ndb.DateTimeProperty()
  # When the entry was last edited.
  last_modified: datetime = ndb.DateTimeProperty()
  # Last modified field of the original imported file
  import_last_modified: datetime = ndb.DateTimeProperty()
  # When the entry was withdrawn.
  withdrawn: datetime = ndb.DateTimeProperty()
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
  purl: list[str] = ndb.StringProperty(repeated=True)
  # Project/package name for the bug.
  project: list[str] = ndb.StringProperty(repeated=True)
  # Package ecosystem for the project.
  ecosystem: list[str] = ndb.StringProperty(repeated=True)
  # Summary for the bug.
  summary: str = ndb.TextProperty()
  # Vulnerability details.
  details: str = ndb.TextProperty()
  # Severity of the bug.
  severities: list[Severity] = ndb.LocalStructuredProperty(
      Severity, repeated=True)
  # Credits for the bug.
  credits: list[Credit] = ndb.LocalStructuredProperty(Credit, repeated=True)
  # Whether or not the bug is public (OSS-Fuzz only).
  public: bool = ndb.BooleanProperty()
  # Reference URL types (dict of url -> type).
  reference_url_types: dict = ndb.JsonProperty()
  # Search indices (auto-populated)
  search_indices: list[str] = ndb.StringProperty(repeated=True)
  # Whether or not the bug has any affected versions (auto-populated).
  has_affected: bool = ndb.BooleanProperty()
  # Source of truth for this Bug.
  source_of_truth: SourceOfTruth = ndb.IntegerProperty(
      default=SourceOfTruth.INTERNAL)
  # Whether the bug is fixed (indexed for querying).
  is_fixed: bool = ndb.BooleanProperty()
  # Database specific.
  database_specific: dict = ndb.JsonProperty()
  # Normalized SEMVER fixed indexes for querying.
  semver_fixed_indexes: list[str] = ndb.StringProperty(repeated=True)
  # Affected packages and versions.
  affected_packages: list[AffectedPackage] = ndb.LocalStructuredProperty(
      AffectedPackage, repeated=True)
  # The source of this Bug.
  source: str = ndb.StringProperty()

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
  def get_by_id(cls, vuln_id, *args, **kwargs) -> Self | None:
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

    # Only attempt to add the Git ecosystem if
    # there are no existing ecosystems present
    if not ecosystems_set:
      for pkg in self.affected_packages:
        for r in pkg.ranges:
          if r.type == 'GIT':
            ecosystems_set.add('GIT')
            break
        if 'GIT' in ecosystems_set:
          break

    # If a withdrawn record has no affected package,
    # assign an '[EMPTY]' ecosystem value for export.
    if not ecosystems_set:
      ecosystems_set.add('[EMPTY]')

    # For all ecosystems that specify a specific version with colon,
    # also add the base name
    ecosystems_set.update({ecosystems.normalize(x) for x in ecosystems_set})

    # Expand the set to include all ecosystem variants.
    ecosystems_set = ecosystems.add_matching_ecosystems(ecosystems_set)

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

    for affected_package in self.affected_packages:
      for affected_range in affected_package.ranges:
        if affected_range.repo_url and affected_range.repo_url != '':
          url_no_https = affected_range.repo_url.split('//')[1]  # remove https
          repo_url_indices = url_no_https.split('/')[1:]  # remove domain
          repo_url_indices.append(affected_range.repo_url)  # add full url
          repo_url_indices.append(url_no_https)  # add url without https://
          search_indices.update(repo_url_indices)

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
        if (not affected_package.package.ecosystem and
            len(affected_package.versions) > _MAX_GIT_VERSIONS_TO_INDEX):
          # Assume that if there is no ecosystem specified, then these versions
          # were enumerated from Git.
          #
          # Mitigate cases where the Git repo tag matching results in too many
          # versions to index for Datastore.
          # It's OK to do this because the primary intended matching mechanism
          # for Git is via commit hash matching instead.
          logging.info(
              'Skipping indexing of git versions for %s '
              'as there are too many (%s).', self.db_id,
              len(affected_package.versions))
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
        raise ValueError(f'{self.db_id} has invalid source {self.source}')

      if source_repo.db_prefix and not any(
          self.db_id.startswith(prefix) for prefix in source_repo.db_prefix):
        raise ValueError(
            f'{self.db_id} has invalid prefix for source {self.source}')

      self.key = ndb.Key(Bug, self.db_id)

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
    self.upstream_raw = list(vulnerability.upstream)

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

  def to_vulnerability(self,
                       include_source=False,
                       include_alias=True,
                       include_upstream=True):
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

    # Note that there is further possible mutation of this field below when
    # `include_alias` is True or `include_upstream` is True
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

    related = self.related
    aliases = []

    if include_alias:
      related_bugs = Bug.query(
          Bug.related == self.db_id, projection=[Bug.db_id]).fetch()
      related_bug_ids = [bug.db_id for bug in related_bugs]
      related = sorted(list(set(related_bug_ids + self.related)))

      alias_group = AliasGroup.query(AliasGroup.bug_ids == self.db_id).get()
      if alias_group:
        aliases = sorted(list(set(alias_group.bug_ids) - {self.db_id}))
        modified = timestamp_pb2.Timestamp()
        modified.FromDatetime(
            max(self.last_modified, alias_group.last_modified))

    upstream = []

    if include_upstream:
      upstream_group = UpstreamGroup.query(
          UpstreamGroup.db_id == self.db_id).get()
      if upstream_group:
        upstream = sorted(upstream_group.upstream_ids)
        modified = timestamp_pb2.Timestamp()
        modified.FromDatetime(
            max(self.last_modified, upstream_group.last_modified))

    result = vulnerability_pb2.Vulnerability(
        schema_version=SCHEMA_VERSION,
        id=self.id(),
        published=published,
        modified=modified,  # Note the three places above where this can be set.
        aliases=aliases,
        related=related,
        upstream=upstream,
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

  @ndb.tasklet
  def to_vulnerability_async(self,
                             include_source=False,
                             include_alias=False,
                             include_upstream=False):
    """Converts to Vulnerability proto and retrieves aliases asynchronously."""
    vulnerability = self.to_vulnerability(
        include_source=include_source,
        include_alias=False,
        include_upstream=False)

    related_bug_ids = yield get_related_async(vulnerability.id)
    vulnerability.related[:] = sorted(
        list(set(related_bug_ids + list(vulnerability.related))))

    if include_alias:
      alias_group = yield get_aliases_async(vulnerability.id)
      if alias_group:
        alias_ids = sorted(list(set(alias_group.bug_ids) - {vulnerability.id}))
        vulnerability.aliases[:] = alias_ids
        modified_time = vulnerability.modified.ToDatetime()
        modified_time = max(alias_group.last_modified, modified_time)
        vulnerability.modified.FromDatetime(modified_time)

    if include_upstream:
      upstream_group = yield get_upstream_async(vulnerability.id)
      if upstream_group:
        vulnerability.upstream = upstream_group.upstream_ids
        modified_time = vulnerability.modified.ToDatetime()
        modified_time = max(upstream_group.last_modified, modified_time)
        vulnerability.modified.FromDatetime(modified_time)
    return vulnerability


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
  file_exts: list[str] = ndb.StringProperty(repeated=True)
  # The hash algorithm used
  file_hash_type: str = ndb.StringProperty()
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
  last_update_date: datetime = ndb.DateTimeProperty()
  # Patterns of files to exclude (regex).
  ignore_patterns: list[str] = ndb.StringProperty(repeated=True)
  # Whether this repository is editable.
  editable: bool = ndb.BooleanProperty(default=False)
  # Default extension.
  extension: str = ndb.StringProperty(default='.yaml')
  # Key path within each file to store the vulnerability.
  key_path: str = ndb.StringProperty()
  # If true, don't analyze any Git ranges.
  ignore_git: bool = ndb.BooleanProperty(default=False)
  # Whether to detect cherypicks or not (slow for large repos).
  detect_cherrypicks: bool = ndb.BooleanProperty(default=True)
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
  db_prefix: list[str] = ndb.StringProperty(repeated=True)
  # Apply strict validation (JSON Schema + linter checks) to this source.
  strict_validation: bool = ndb.BooleanProperty(default=False)

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


class AliasGroup(ndb.Model):
  """Alias group."""
  bug_ids: list[str] = ndb.StringProperty(repeated=True)
  last_modified: datetime = ndb.DateTimeProperty()


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
  upstream_ids: list[str] = ndb.StringProperty(repeated=True)
  # Date when group was last modified
  last_modified: datetime = ndb.DateTimeProperty()


class ImportFindings(enum.IntEnum):
  """The possible quality findings about an individual record."""
  NONE = 0
  DELETED = 1
  INVALID_JSON = 2
  INVALID_PACKAGE = 3
  INVALID_PURL = 4
  INVALID_VERSION = 5
  INVALID_COMMIT = 6
  INVALID_RANGE = 7
  BAD_ALIASED_CVE = 8


class ImportFinding(ndb.Model):
  """Quality findings about an individual record."""
  bug_id: str = ndb.StringProperty()
  source: str = ndb.StringProperty()
  findings: list[ImportFindings] = ndb.IntegerProperty(repeated=True)
  first_seen: datetime = ndb.DateTimeProperty()
  last_attempt: datetime = ndb.DateTimeProperty()

  def _pre_put_hook(self):  # pylint: disable=arguments-differ
    """Pre-put hook for setting key."""
    if not self.key:  # pylint: disable=access-member-before-definition
      self.key = ndb.Key(ImportFinding, self.bug_id)

  def to_proto(self):
    """Converts to ImportFinding proto."""
    return importfinding_pb2.ImportFinding(
        bug_id=self.bug_id,
        source=self.source,
        findings=self.findings,  # type: ignore
        first_seen=self.first_seen.timestamp_pb(),  #type: ignore
        last_attempt=self.last_attempt.timestamp_pb(),  #type: ignore
    )


def get_source_repository(source_name: str) -> SourceRepository:
  """Get source repository."""
  return SourceRepository.get_by_id(source_name)


def sorted_events(ecosystem, range_type, events) -> list[AffectedEvent]:
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


@ndb.tasklet
def get_aliases_async(bug_id: str) -> ndb.Future:
  """Gets aliases asynchronously."""
  alias_group = yield AliasGroup.query(AliasGroup.bug_ids == bug_id).get_async()
  return alias_group


@ndb.tasklet
def get_related_async(bug_id: str) -> ndb.Future:
  """Gets related bugs asynchronously."""
  related_bugs = yield Bug.query(
      Bug.related == bug_id, projection=[Bug.db_id]).fetch_async()
  related_bug_ids = [bug.db_id for bug in related_bugs]
  return related_bug_ids


@ndb.tasklet
def get_upstream_async(bug_id: str) -> ndb.Future:
  """Gets upstream bugs asynchronously."""
  upstream_group = yield UpstreamGroup.query(
      UpstreamGroup.db_id == bug_id).get_async()
  return upstream_group
