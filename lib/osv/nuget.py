# Copyright 2022 Google LLC
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
"""NuGet version parser."""

import functools
import re

from . import semver_index

# This relies on a strict SemVer implementation.
# Differences from SemVer are described at
# https://docs.microsoft.com/en-us/nuget/concepts/package-versioning
#  - Optional 4th component (x.y.z.R).
#  - Prerelease components are compared case insensitively.
#  - Non-major version segments are optional. e.g. "1" is a valid version
#    number.


def _extract_revision(str_version):
  """Extract revision (4th component) from version number (if any)."""
  # e.g. '1.0.0.0-prerelease'
  pattern = re.compile(r'^(\d+)(\.\d+)(\.\d+)(\.\d+)(.*)')
  match = pattern.match(str_version)
  if not match:
    return str_version, 0

  return (''.join(
      (match.group(1), match.group(2), match.group(3), match.group(5))),
          int(match.group(4)[1:]))


@functools.total_ordering
class Version:
  """NuGet version."""

  def __init__(self, base_semver, revision):
    self._base_semver = base_semver
    if self._base_semver.prerelease:
      self._base_semver = self._base_semver.replace(
          prerelease=base_semver.prerelease.lower())
    self._revision = revision

  def __eq__(self, other):
    return (self._base_semver == other._base_semver and
            self._revision == other._revision)

  def __lt__(self, other):
    if (self._base_semver.replace(prerelease='') == other._base_semver.replace(
        prerelease='')):
      # If the first three components are the same, compare the revision.
      if self._revision != other._revision:
        return self._revision < other._revision

    # Revision is the same, so ignore it for comparison purposes.
    return self._base_semver < other._base_semver

  @classmethod
  def from_string(cls, str_version):
    str_version = semver_index.coerce(str_version)
    str_version, revision = _extract_revision(str_version)
    return Version(semver_index.parse(str_version), revision)
