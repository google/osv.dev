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


class PackageInfo(ndb.Model):
  """Package info."""
  # The latest tag for the package.
  latest_tag = ndb.StringProperty()


class PackageTagInfo(ndb.Model):
  """Project tag information."""
  # The name of the package.
  package = ndb.StringProperty()
  # The ecosystem for the package.
  ecosystem = ndb.StringProperty()
  # The tag.
  tag = ndb.StringProperty()
  # List of public bugs.
  bugs = ndb.StringProperty(repeated=True)
  # List of private bugs.
  bugs_private = ndb.StringProperty(repeated=True)


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

  # Status of the bug.
  status = ndb.IntegerProperty()
  # Timestamp when Bug was allocated.
  timestamp = ndb.DateTimeProperty()
  # When the entry was last edited.
  last_modified = ndb.DateTimeProperty()
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
  affected = ndb.StringProperty(repeated=True)
  # List of normalized versions for fuzzy matching.
  affected_fuzzy = ndb.StringProperty(repeated=True)
  # OSS-Fuzz issue ID.
  issue_id = ndb.StringProperty()
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
  # Sort key.
  sort_key = ndb.StringProperty()
  # Source of truth for this Bug.
  source_of_truth = ndb.IntegerProperty(default=SourceOfTruth.INTERNAL)
  # Whether the bug is fixed (indexed for querying).
  is_fixed = ndb.BooleanProperty()

  def id(self):
    """Get the bug ID."""
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
    # OSV allocated bug IDs are stored without the prefix.
    if vuln_id.startswith(cls.OSV_ID_PREFIX):
      vuln_id = vuln_id[len(cls.OSV_ID_PREFIX):]

    return super().get_by_id(vuln_id, *args, **kwargs)

  def _pre_put_hook(self):
    """Pre-put hook for populating search indices."""
    self.search_indices = []
    if self.project:
      self.search_indices.append(self.project)

    key_parts = self.key.id().split('-')
    self.search_indices.append(self.key.id())
    self.search_indices.extend(key_parts)

    self.has_affected = bool(self.affected)
    self.affected_fuzzy = bug.normalize_tags(self.affected)

    self.sort_key = key_parts[0] + '-' + key_parts[1].zfill(7)
    if not self.last_modified:
      self.last_modified = utcnow()

    self.is_fixed = any(
        affected_range.fixed for affected_range in self.affected_ranges)

  def update_from_vulnerability(self, vulnerability):
    """Set fields from vulnerability."""
    self.summary = vulnerability.summary
    self.details = vulnerability.details
    if vulnerability.severity != vulnerability_pb2.Severity.NONE:
      self.severity = vulnerability_pb2.Severity.Name(vulnerability.severity)
    self.reference_url_types = {
        ref.url: vulnerability_pb2.Reference.Type.Name(ref.type)
        for ref in vulnerability.references
    }
    if vulnerability.HasField('modified'):
      self.last_modified = vulnerability.modified.ToDatetime()
    if vulnerability.HasField('published'):
      self.timestamp = vulnerability.published.ToDatetime()
    self.project = vulnerability.package.name
    self.ecosystem = vulnerability.package.ecosystem
    self.affected = list(vulnerability.affects.versions)

    self.affected_ranges = []
    for affected_range in vulnerability.affects.ranges:
      self.affected_ranges.append(
          AffectedRange(
              type=vulnerability_pb2.AffectedRange.Type.Name(
                  affected_range.type),
              repo_url=affected_range.repo,
              introduced=affected_range.introduced or '',
              fixed=affected_range.fixed or ''))

  def to_vulnerability(self):
    """Convert to Vulnerability proto."""
    package = vulnerability_pb2.Package(
        name=self.project, ecosystem=self.ecosystem)

    affects = vulnerability_pb2.Affects(versions=self.affected)
    for affected_range in self.affected_ranges:
      affects.ranges.add(
          type=vulnerability_pb2.AffectedRange.Type.Value(affected_range.type),
          repo=affected_range.repo_url,
          introduced=affected_range.introduced,
          fixed=affected_range.fixed)

    if self.severity:
      severity = vulnerability_pb2.Severity.Value(self.severity)
    else:
      severity = vulnerability_pb2.Severity.NONE

    details = self.details
    if self.status == bug.BugStatus.INVALID:
      affects = None
      details = 'INVALID'
      severity = vulnerability_pb2.Severity.NONE

    if self.last_modified:
      modified = timestamp_pb2.Timestamp()
      modified.FromDatetime(self.last_modified)
    else:
      modified = None

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
        summary=self.summary,
        details=details,
        package=package,
        severity=severity,
        affects=affects,
        references=references)
    return result


class SourceRepository(ndb.Model):
  """Source repository."""
  # The name of the source.
  name = ndb.StringProperty()
  # The repo URL for the source.
  repo_url = ndb.StringProperty()
  # The username to use for SSH auth.
  repo_username = ndb.StringProperty()
  # The directory in the repo where Vulnerability data is stored.
  directory_path = ndb.StringProperty()
  # Last synced hash.
  last_synced_hash = ndb.StringProperty()
  # Last date recurring updates were requested.
  last_update_date = ndb.DateProperty()
  # Patterns of files to exclude (regex).
  ignore_patterns = ndb.StringProperty(repeated=True)
  # It true, don't expand on git ranges.
  ignore_git = ndb.BooleanProperty(default=False)

  def ignore_file(self, file_path):
    """Return whether or not we should be ignoring a file."""
    if not self.ignore_patterns:
      return False

    file_name = os.path.basename(file_path)
    for pattern in self.ignore_patterns:
      if re.match(pattern, file_name):
        return True

    return False
