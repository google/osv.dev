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

import re

import semver

_PAD_WIDTH = 8
_FAKE_PRE_WIDTH = 16


def _strip_leading_v(version):
  """Strip leading v from the version, if any."""
  # Versions starting with "v" aren't valid SemVer, but we handle them just in
  # case.
  if version.startswith('v'):
    return version[1:]

  return version


def _remove_leading_zero(component):
  """Remove leading zeros from a component."""
  if component[0] == '.':
    return '.' + str(int(component[1:]))

  return str(int(component))


def _coerce_suffix(suffix):
  """Coerce a potentially invalid semver suffix into a valid semver suffix.

  Removes leading zeros from the pre-release suffix and modifies empty
  components to allow earlier SemVer specs (specifically 2.0.0-rc.1) to be
  parsed.

  Empty components are replaced with '-' (i.e 1.0.0-a..0 -> 1.0.0-a.-.0) which
  mostly preserves ordering."""

  if not suffix:
    return suffix

  suffix_pattern = re.compile(r'^(-[^+]*)?(\+.*)?(.*)$')
  match = suffix_pattern.match(suffix)

  pre = ''
  if match.group(1):
    pre_components = []
    for component in match.group(1)[1:].split('.'):
      if not component:
        pre_components.append('-')
      elif component.isdigit():
        pre_components.append(_remove_leading_zero(component))
      else:
        pre_components.append(component)
    pre = '-' + '.'.join(pre_components)

  build = ''
  if match.group(2):
    build_components = []
    for component in match.group(2)[1:].split('.'):
      if not component:
        build_components.append('-')
      else:
        build_components.append(component)
    build = '+' + '.'.join(build_components)

  return pre + build + match.group(3)


def coerce(version: str):
  """Coerce a potentially invalid semver into valid semver."""
  version = _strip_leading_v(version)
  version_pattern = re.compile(r'^(\d+)(\.\d+)?(\.\d+)?(.*)$')
  match = version_pattern.match(version)
  if not match:
    return version

  return (_remove_leading_zero(match.group(1)) +
          _remove_leading_zero(match.group(2) or '.0') +
          _remove_leading_zero(match.group(3) or '.0') +
          _coerce_suffix(match.group(4)))


def is_valid(version):
  """Returns whether or not the version is a valid semver."""
  return semver.Version.is_valid(_strip_leading_v(version))


def parse(version: str):
  """Parse a SemVer."""
  return semver.Version.parse(coerce(version))


def normalize(version):
  """Normalize semver version for indexing (to allow for lexical
  sorting/filtering)."""
  version = parse(version)

  # Precedence rules: https://semver.org/#spec-item-11

  # 1. Precedence MUST be calculated by separating the version into major,
  # minor, patch and pre-release identifiers in that order (Build metadata does
  # not figure into precedence).
  #
  # Normalization: Per spec build metadata is ignored.

  # 2. Precedence is determined by the first difference when comparing each of
  # these identifiers from left to right as follows: Major, minor, and patch
  # versions are always compared numerically.
  #
  # Normalization: Pad the components with '0' to allow for lexical ordering of
  # numbers.
  core_parts = '{}.{}.{}'.format(
      str(version.major).rjust(_PAD_WIDTH, '0'),
      str(version.minor).rjust(_PAD_WIDTH, '0'),
      str(version.patch).rjust(_PAD_WIDTH, '0'))

  # 3. When major, minor, and patch are equal, a pre-release version has lower
  # precedence than a normal version:
  #
  # Normalization: Attach a very long fake prerelease version that is most
  # likely to come after any real prelease version.
  if not version.prerelease:
    pre = 'z' * _FAKE_PRE_WIDTH
    return f'{core_parts}-{pre}'

  pre = normalize_prerelease(version.prerelease)
  return f'{core_parts}-{pre}'


def normalize_prerelease(prerelease):
  """Normalize semver pre-release version suffix for indexing (to allow for
  lexical sorting/filtering)."""
  # 4. Precedence for two pre-release versions with the same major, minor, and
  # patch version MUST be determined by comparing each dot separated identifier
  # from left to right until a difference is found as follows:
  #
  # Normalization: Pad the components.
  pre_components = []
  for component in prerelease.split('.'):
    # 3. Numeric identifiers always have lower precedence than non-numeric
    # identifiers.
    #
    # Normalization: Pad numeric components with '0', and prefix alphanumeric
    # with a single '1' (to ensure they always come after).
    if component.isdigit():
      # 1. Identifiers consisting of only digits are compared numerically.
      pre_components.append(component.rjust(_PAD_WIDTH, '0'))
    else:
      # 2. Identifiers with letters or hyphens are compared lexically in ASCII
      # sort order.
      pre_components.append('1' + component)

  # 4. A larger set of pre-release fields has a higher precedence than a smaller
  # set, if all of the preceding identifiers are equal.
  #
  # Consistent with lexical sorting after normalization.
  return '.'.join(pre_components)
