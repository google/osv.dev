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
"""SemVer indexer."""

from __future__ import annotations

import re
from typing import List, Tuple, Union # Added Union for PrereleaseItemType

import semver

_PAD_WIDTH = 8
_FAKE_PRE_WIDTH = 16

# Type for items in semver.Version.prerelease tuple
PrereleaseItemType = Union[str, int]


def _strip_leading_v(version: str) -> str:
  """Strip leading v from the version, if any."""
  # Versions starting with "v" aren't valid SemVer, but we handle them just in
  # case.
  if version.startswith('v'):
    return version[1:]

  return version


def _remove_leading_zero(component: str) -> str:
  """Remove leading zeros from a component."""
  if not component: # Guard against empty component string
      return component
  if component.startswith('.') and len(component) > 1 and component[1:].isdigit():
    return '.' + str(int(component[1:]))
  if component.isdigit():
    return str(int(component))
  # Return component as is if not purely numeric or not starting with '.' + numeric
  return component


def _coerce_suffix(suffix: str) -> str:
  """Coerce a potentially invalid semver suffix into a valid semver suffix.

  Removes leading zeros from the pre-release suffix and modifies empty
  components to allow earlier SemVer specs (specifically 2.0.0-rc.1) to be
  parsed.

  Empty components are replaced with '-' (i.e 1.0.0-a..0 -> 1.0.0-a.-.0) which
  mostly preserves ordering."""

  if not suffix:
    return suffix

  # Regex to capture pre-release, build metadata, and any remaining characters.
  # It assumes typical semver suffix structure like -pre+build or just -pre or +build.
  suffix_pattern = re.compile(r'^(-[^+]*)?(\+.*)?$')
  match = suffix_pattern.match(suffix)

  # If the suffix doesn't match expected semver structure (e.g., contains unexpected chars not part of pre/build)
  # return it as is, or handle error, depending on desired strictness.
  # For now, this regex is quite greedy for `pre` if no `+` is found.
  if not match:
    return suffix # Or raise error, or attempt further specific parsing

  pre_part_str: str = match.group(1) or ""
  build_part_str: str = match.group(2) or ""

  final_pre: str = ''
  if pre_part_str: # If there's a pre-release part (e.g., "-alpha.1")
    pre_components: List[str] = []
    # Strip leading '-' then split
    for component in pre_part_str[1:].split('.'):
      if not component: # Empty component
        pre_components.append('-')
      elif component.isdigit():
        pre_components.append(_remove_leading_zero(component))
      else:
        pre_components.append(component)
    final_pre = '-' + '.'.join(pre_components)

  final_build: str = ''
  if build_part_str: # If there's a build metadata part (e.g., "+build.123")
    build_components: List[str] = []
    # Strip leading '+' then split
    for component in build_part_str[1:].split('.'):
      if not component: # Empty component
        build_components.append('-')
      else:
        # Build metadata components don't have numeric vs alphanumeric distinction for coercion typically
        build_components.append(component)
    final_build = '+' + '.'.join(build_components)

  # This assumes that the original regex `(.*)$` for group(3) was to catch
  # unexpected characters. If such characters are present and not part of pre/build,
  # this simplified regex might not capture them.
  # If group(3) was vital, the regex and logic need to be more complex.
  # Given typical semver, suffixes are usually just pre-release and build.
  return final_pre + final_build


def coerce(version_str: str) -> str: # Renamed version to version_str
  """Coerce a potentially invalid semver into valid semver."""
  version_str = _strip_leading_v(version_str)
  # Regex to separate core (1.2.3) from suffix (-pre+build)
  version_pattern = re.compile(r'^(\d+)(\.\d+)?(\.\d+)?(.*)$')
  match = version_pattern.match(version_str)
  if not match:
    return version_str # Return original if not matching basic structure

  # Extracting with defaults for optional minor/patch
  major = match.group(1)
  minor = match.group(2) or '.0'
  patch = match.group(3) or '.0'
  suffix = match.group(4) or ''

  return (_remove_leading_zero(major) +
          _remove_leading_zero(minor) + # Minor includes leading '.'
          _remove_leading_zero(patch) + # Patch includes leading '.'
          _coerce_suffix(suffix))


def is_valid(version: str) -> bool:
  """Returns whether or not the version is a valid semver."""
  # coerce attempts to fix some issues, then is_valid checks.
  # Alternatively, could check _strip_leading_v(version) directly if coerce is too permissive.
  return semver.Version.is_valid(coerce(_strip_leading_v(version)))


def parse(version_str: str) -> semver.Version: # Renamed version to version_str
  """Parse a SemVer. Returns a semver.Version object."""
  return semver.Version.parse(coerce(version_str))


def normalize(version_str: str) -> str: # Renamed version to version_str
  """Normalize semver version for indexing (to allow for lexical
  sorting/filtering)."""
  version_info: semver.Version = parse(version_str) # Renamed version to version_info

  # Precedence rules: https://semver.org/#spec-item-11
  # 1. Build metadata does not figure into precedence. (Handled by semver library)
  # 2. Major, minor, and patch versions are always compared numerically.
  #    Normalization: Pad the components with '0'.
  core_parts = '{}.{}.{}'.format(
      str(version_info.major).rjust(_PAD_WIDTH, '0'),
      str(version_info.minor).rjust(_PAD_WIDTH, '0'),
      str(version_info.patch).rjust(_PAD_WIDTH, '0'))

  # 3. When major, minor, and patch are equal, a pre-release version has lower
  #    precedence than a normal version.
  #    Normalization: Attach a very long fake prerelease version for non-prerelease,
  #    or normalized actual prerelease.
  if not version_info.prerelease:
    # For non-prerelease versions, use a string that sorts after any valid prerelease.
    # 'z'*_FAKE_PRE_WIDTH should work if prereleases are typically shorter or start with earlier chars.
    pre_normalized = 'z' * _FAKE_PRE_WIDTH
  else:
    # version_info.prerelease is a tuple e.g. ('alpha', 1). Need to convert to string.
    prerelease_str: str = '.'.join(map(str, version_info.prerelease))
    pre_normalized = normalize_prerelease(prerelease_str)

  return f'{core_parts}-{pre_normalized}'


def normalize_prerelease(prerelease_str: str) -> str: # Renamed prerelease to prerelease_str
  """Normalize semver pre-release version suffix for indexing (to allow for
  lexical sorting/filtering)."""
  # Precedence for two pre-release versions... determined by comparing each dot separated identifier...
  # Normalization: Pad the components.
  pre_components: List[str] = []
  if not prerelease_str: # Handle empty prerelease string case
      return ""

  for component in prerelease_str.split('.'):
    # Numeric identifiers always have lower precedence than non-numeric identifiers.
    # Normalization: Pad numeric components with '0', and prefix alphanumeric
    # with a '1' (to ensure they always come after numeric strings of same length).
    if component.isdigit():
      # Identifiers consisting of only digits are compared numerically.
      pre_components.append(component.rjust(_PAD_WIDTH, '0'))
    else:
      # Identifiers with letters or hyphens are compared lexically in ASCII sort order.
      # Prepending '1' makes "alpha" sort after "99".
      # Ensure component is not empty before prepending, though split shouldn't produce empty ones unless ".."
      if component: # Non-empty alphanumeric component
          pre_components.append('1' + component.rjust(_PAD_WIDTH -1, '_')) # Pad to keep length somewhat consistent
      else: # Empty component (e.g. from "alpha..1") - treat as lowest precedence string part?
          pre_components.append('1' + '_' * (_PAD_WIDTH -1) )


  # A larger set of pre-release fields has a higher precedence than a smaller set,
  # if all of the preceding identifiers are equal. (Lexical sort handles this).
  return '.'.join(pre_components)
