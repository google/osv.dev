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
from google.protobuf import timestamp_pb2

# pylint: disable=relative-beyond-top-level
from . import bug
from . import semver_index
from . import sources
from . import vulnerability_pb2


def _check_valid_severity(prop, value):
  """Check valid severity."""
  del prop

  if value not in ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'):
    raise ValueError('Invalid severity: ' + value)


def _check_valid_range_type(prop, value):
  """Check valid range type."""
  del prop

  if value not in ('GIT', 'SEMVER', 'ECOSYSTEM'):
    raise ValueError('Invalid severity: ' + value)


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
  summary = ndb.StringProperty()
  # Vulnerability details.
  details = ndb.StringProperty()
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
  summary = ndb.StringProperty()
  # Vulnerability details.
  details = ndb.StringProperty()
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


class SourceOfTruth(enum.IntEnum):
  """Source of truth."""
  NONE = 0
  # Internal to OSV (e.g. private OSS-Fuzz bugs).
  INTERNAL = 1
  # Vulnerabilities that are available in a public repo.
  SOURCE_REPO = 2


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
  # All affected ranges.
  affected_ranges = ndb.StructuredProperty(AffectedRange, repeated=True)
  # List of affected versions.
  affected = ndb.TextProperty(repeated=True)
  # List of normalized versions indexed for fuzzy matching.
  affected_fuzzy = ndb.StringProperty(repeated=True)
  # OSS-Fuzz issue ID.
  issue_id = ndb.StringProperty()
  # Package URL for this package.
  purl = ndb.StringProperty()
  # Project/package name for the bug.
  project = ndb.StringProperty()
  # Package ecosystem for the project.
  ecosystem = ndb.StringProperty()
  # Summary for the bug.
  summary = ndb.StringProperty()
  # Vulnerability details.
  details = ndb.StringProperty()
  # Severity of the bug.
  severity = ndb.StringProperty(validator=_check_valid_severity)
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
  # Ecosystem specific.
  ecosystem_specific = ndb.JsonProperty()
  # Normalized SEMVER fixed indexes for querying.
  semver_fixed_indexes = ndb.StringProperty(repeated=True)
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
    for affected_range in self.affected_ranges:
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
    if self.project:
      search_indices.update(self._tokenize(self.project))

    if self.ecosystem:
      search_indices.update(self._tokenize(self.ecosystem))

    self.search_indices = sorted(list(search_indices))
    self.has_affected = bool(self.affected) or any(
        r.type in ('SEMVER', 'ECOSYSTEM') for r in self.affected_ranges)
    self.affected_fuzzy = bug.normalize_tags(self.affected)

    if not self.last_modified:
      self.last_modified = utcnow()

    self.is_fixed = any(
        affected_range.fixed for affected_range in self.affected_ranges)

    self.semver_fixed_indexes = []
    for affected_range in self.affected_ranges:
      if affected_range.type == 'SEMVER':
        fixed = affected_range.fixed or self._NOT_FIXED_SEMVER
        self.semver_fixed_indexes.append(semver_index.normalize(fixed))

    if self.source_id:
      self.source, _ = sources.parse_source_id(self.source_id)

    if not self.source:
      raise ValueError('Source not specified for Bug.')

    if not self.db_id:
      raise ValueError('DB ID not specified for Bug.')

    if not self.key:
      source_repo = get_source_repository(self.source)
      if not source_repo:
        raise ValueError(f'Invalid source {self.source}')

      if source_repo.db_prefix and self.db_id.startswith(source_repo.db_prefix):
        key_id = self.db_id
      else:
        key_id = f'{self.source}:{self.db_id}'

      self.key = ndb.Key(Bug, key_id)

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

    self.project = vulnerability.package.name
    self.ecosystem = vulnerability.package.ecosystem
    if vulnerability.package.purl:
      self.purl = vulnerability.package.purl

    self.affected = list(vulnerability.affects.versions)
    self.aliases = list(vulnerability.aliases)
    self.related = list(vulnerability.related)

    vuln_dict = sources.vulnerability_to_dict(vulnerability)
    if vulnerability.database_specific:
      self.database_specific = vuln_dict['database_specific']

    if vulnerability.ecosystem_specific:
      self.ecosystem_specific = vuln_dict['ecosystem_specific']

    self.affected_ranges = []
    for affected_range in vulnerability.affects.ranges:
      self.affected_ranges.append(
          AffectedRange(
              type=vulnerability_pb2.AffectedRange.Type.Name(
                  affected_range.type),
              repo_url=affected_range.repo,
              introduced=affected_range.introduced or '',
              fixed=affected_range.fixed or ''))

  def to_vulnerability(self, include_source=False):
    """Convert to Vulnerability proto."""
    package = vulnerability_pb2.Package(
        name=self.project, ecosystem=self.ecosystem, purl=self.purl)

    affects = vulnerability_pb2.Affects(versions=self.affected)
    for affected_range in self.affected_ranges:
      affects.ranges.add(
          type=vulnerability_pb2.AffectedRange.Type.Value(affected_range.type),
          repo=affected_range.repo_url,
          introduced=affected_range.introduced,
          fixed=affected_range.fixed)

    details = self.details
    if self.status == bug.BugStatus.INVALID:
      affects = None
      details = 'INVALID'

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

    result = vulnerability_pb2.Vulnerability(
        id=self.id(),
        published=published,
        modified=modified,
        aliases=self.aliases,
        related=self.related,
        withdrawn=withdrawn,
        summary=self.summary,
        details=details,
        package=package,
        affects=affects,
        references=references)

    if self.ecosystem_specific:
      result.ecosystem_specific.update(self.ecosystem_specific)
    if self.database_specific:
      result.database_specific.update(self.database_specific)

    if self.source and include_source:
      source_repo = get_source_repository(self.source)
      if not source_repo or not source_repo.link:
        return result

      result.database_specific.update({
          'source': source_repo.link + sources.source_path(source_repo, self),
      })

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
