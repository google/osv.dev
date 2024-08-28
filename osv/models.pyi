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

import enum
import re
import os
from datetime import datetime

from typing import List, Self

from google.cloud import ndb


class ndbModel(ndb.Model):
  key: ndb.Key


class IDCounter(ndbModel):
  next_id: str


class AffectedCommits(ndbModel):
  # The main bug ID.
  bug_id: str
  # The commit hash.
  commits: list[bytes]
  # Whether or not the bug is public.
  public: bool
  # The page for this batch of commits.
  page: int


class RegressResult(ndbModel):
  """Regression results."""
  # The commit hash.
  commit: str
  # Vulnerability summary.
  summary: str
  # Vulnerability details.
  details: str
  # Error (if any).
  error: str
  # OSS-Fuzz issue ID.
  issue_id: str
  # Project for the bug.
  project: str
  # Package ecosystem for the project.
  ecosystem: str
  # Repo URL.
  repo_url: str
  # Severity of the bug.
  severity: str
  # Reference URLs.
  reference_urls: list[str]
  # Source timestamp.
  timestamp: datetime


class FixResult(ndbModel):
  """Fix results."""
  # The commit hash.
  commit: str
  # Vulnerability summary.
  summary: str
  # Vulnerability details.
  details: str
  # Error (if any).
  error: str
  # OSS-Fuzz issue ID.
  issue_id: str
  # Project for the bug.
  project: str
  # Package ecosystem for the project.
  ecosystem: str
  # Repo URL.
  repo_url: str
  # Severity of the bug.
  severity: str
  # Reference URLs.
  reference_urls: list[str]
  # Source timestamp.
  timestamp: datetime


class AffectedEvent(ndbModel):
  """Affected event."""
  type: str
  value: str


class AffectedRange2(ndbModel):
  """Affected range."""
  # Type of range.
  type: str
  # Repo URL.
  repo_url: str
  # Events.
  events: list[AffectedEvent]


class SourceOfTruth(enum.IntEnum):
  """Source of truth."""
  NONE = 0
  # Internal to OSV (e.g. private OSS-Fuzz bugs).
  INTERNAL = 1
  # Vulnerabilities that are available in a public repo.
  SOURCE_REPO = 2


class Package(ndbModel):
  """Package."""
  ecosystem: str
  name: str
  purl: str


class Severity(ndbModel):
  """Severity."""
  type: str
  score: str


class AffectedPackage(ndbModel):
  """Affected packages."""
  # The affected package identifier.
  package: Package
  # The list of affected ranges.
  ranges: list[AffectedRange2]
  # The list of explicit affected versions.
  versions: list[str]
  # Database specific metadata.
  database_specific: dict
  # Ecosystem specific metadata.
  ecosystem_specific: dict
  # Severity of the bug.
  severities: list[Severity]


class Credit(ndbModel):
  """Credits."""
  name: str
  contact: list[str]
  type: str


class Bug(ndbModel):
  """Bug entity."""
  OSV_ID_PREFIX = 'OSV-'
  # Very large fake version to use when there is no fix available.
  _NOT_FIXED_SEMVER = '999999.999999.999999'

  # Display ID as used by the source database. The full qualified database that
  # OSV tracks this as may be different.
  db_id: str
  # Other IDs this bug is known as.
  aliases: list[str]
  # Related IDs.
  related: list[str]
  # Status of the bug.
  status: int
  # Timestamp when Bug was allocated.
  timestamp: datetime
  # When the entry was last edited.
  last_modified: datetime
  # Last modified field of the original imported file
  import_last_modified: datetime
  # When the entry was withdrawn.
  withdrawn: datetime
  # The source identifier.
  # For OSS-Fuzz, this oss-fuzz:<ClusterFuzz testcase ID>.
  # For others this is <source>:<path/to/source>.
  source_id: str
  # The main fixed commit (from bisection).
  fixed: str
  # The main regressing commit (from bisection).
  regressed: str
  # List of affected versions.
  affected: list[str]
  # List of normalized versions indexed for fuzzy matching.
  affected_fuzzy: list[str]
  # OSS-Fuzz issue ID.
  issue_id: str
  # Package URL for this package.
  purl: list[str]
  # Project/package name for the bug.
  project: list[str]
  # Package ecosystem for the project.
  ecosystem: list[str]
  # Summary for the bug.
  summary: str
  # Vulnerability details.
  details: str
  # Severity of the bug.
  severities: list[Severity]
  # Credits for the bug.
  credits: list[Credit]
  # Whether or not the bug is public (OSS-Fuzz only).
  public: bool
  # Reference URL types (dict of url -> type).
  reference_url_types: dict
  # Search indices (auto-populated)
  search_indices: list[str]
  # Whether or not the bug has any affected versions (auto-populated).
  has_affected: bool
  # Source of truth for this Bug.
  source_of_truth: SourceOfTruth
  # Whether the bug is fixed (indexed for querying).
  is_fixed: bool
  # Database specific.
  database_specific: dict
  # Normalized SEMVER fixed indexes for querying.
  semver_fixed_indexes: list[str]
  # Affected packages and versions.
  affected_packages: list[AffectedPackage]
  # The source of this Bug.
  source: str


class RepoIndex(ndbModel):
  """RepoIndex entry"""
  # The dependency name
  name: str
  # The base cpe without the version
  base_cpe: str
  # The repository commit
  commit: bytes
  # The source address
  repo_addr: str
  # The scanned file extensions
  file_exts: list[str]
  # The hash algorithm used
  file_hash_type: str
  # The repository type
  repo_type: str
  # A bitmap of which buckets are empty
  empty_bucket_bitmap: bytes
  # Number of files in this repo
  file_count: int
  # Tag name of the source
  tag: str


class FileResult(ndbModel):
  """FileResult entry containing the path and hash"""
  # The hash value of the file
  hash: bytes
  # The file path
  path: str


class RepoIndexBucket(ndbModel):
  """RepoIndexResult entries containing the actual hash values"""
  # The file results per file
  node_hash: bytes
  # number of files this hash represents
  files_contained: int


class SourceRepositoryType(enum.IntEnum):
  """SourceRepository type."""
  GIT = 0
  BUCKET = 1
  REST_ENDPOINT = 2


class SourceRepository(ndbModel):
  """Source repository."""
  # The SourceRepositoryType of the repository.
  type: int
  # The name of the source.
  name: str
  # The repo URL for the source for SourceRepositoryType.GIT.
  repo_url: str
  # The username to use for SSH auth for SourceRepositoryType.GIT.
  repo_username: str
  # Optional branch for repo for SourceRepositoryType.GIT.
  repo_branch: str
  # The API endpoint for SourceRepositoryType.REST_ENDPOINT.
  rest_api_url: str
  # Bucket name for SourceRepositoryType.BUCKET.
  bucket: str
  # Vulnerability data not under this path is ignored by the importer.
  directory_path: str
  # Last synced hash for SourceRepositoryType.GIT.
  last_synced_hash: str
  # Last date recurring updates were requested.
  last_update_date: datetime
  # Patterns of files to exclude (regex).
  ignore_patterns: list[str]
  # Whether this repository is editable.
  editable: bool
  # Default extension.
  extension: str
  # Key path within each file to store the vulnerability.
  key_path: str
  # If true, don't analyze any Git ranges.
  ignore_git: bool
  # Whether to detect cherypicks or not (slow for large repos).
  detect_cherrypicks: bool
  # Whether to populate "affected[].versions" from Git ranges.
  versions_from_repo: bool
  # Ignore last import time once (SourceRepositoryType.BUCKET).
  ignore_last_import_time: bool
  # HTTP link prefix to individual OSV source records.
  link: str
  # HTTP link prefix to individual vulnerability records for humans.
  human_link: str
  # DB prefix, if the database allocates its own.
  # https://ossf.github.io/osv-schema/#id-modified-fields
  db_prefix: list[str]

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


class AliasGroup(ndbModel):
  """Alias group."""
  bug_ids: list[str]
  last_modified: datetime


class AliasAllowListEntry(ndbModel):
  """Alias group allow list entry."""
  bug_id: str


class AliasDenyListEntry(ndbModel):
  """Alias group deny list entry."""
  bug_id: str


def get_source_repository(source_name):
  ...


def sorted_events(ecosystem, range_type, events) -> list[AffectedEvent]:
  ...


def get_aliases_async(bug_id) -> ndb.Future:
  ...


def get_related_async(bug_id) -> ndb.Future:
  ...
