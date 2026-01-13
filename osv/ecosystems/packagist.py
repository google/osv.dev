# Copyright 2025 Google LLC
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
"""Packagist ecosystem helper."""

import json
import re
from typing import List

from . import config
from .ecosystems_base import EnumerableEcosystem, EnumerateError
from ..request_helper import RequestError, RequestHelper


class PackagistVersion:
  # pylint: disable=line-too-long
  """
  Follows the packagist version ordering, which is recommended to be semver, but
  not enforced to be semver. The php standard version comparison code written in
  C is located here:
  https://github.com/php/php-src/blob/master/ext/standard/versioning.c

  The function first replaces _, - and + with a dot . in the version strings and
  also inserts dots . before and after any non number so that for example
  '4.3.2RC1' becomes '4.3.2.RC.1'. Then it compares the parts starting from
  left to right.

  If a part contains special version strings these are handled in the following
  order:
  any string not found in this list < dev < alpha = a < beta = b < RC = rc < # < pl = p.
  This way not only versions with different levels like '4.1' and '4.1.2' can be
  compared but also any PHP specific version containing development state.

  ---

  ## Known differences:
  The following are some examples of known differences between this python
  implementation and the C implementation of PHP

  - In this version, special version strings need to exactly match to not be
    considered "any other string", while in the original implementation the
    string only need to start with one of the listed strings.
  """
  # pylint: enable=line-too-long

  version_str: str
  canonicalized_version: str

  def __init__(self, version: str):
    self.version_str = version
    self.canonicalized_version = self.php_canonicalize_version(version)

  def __str__(self) -> str:
    return self.version_str

  def __hash__(self):
    return self.canonicalized_version

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.__cmp__(other) == 0

  def __lt__(self, other):
    return self.__cmp__(other) < 0

  def __le__(self, other):
    return self.__cmp__(other) <= 0

  def __gt__(self, other):
    return self.__cmp__(other) > 0

  def __ge__(self, other):
    return self.__cmp__(other) >= 0

  def __cmp__(self, other):
    return self.php_version_compare(self.version_str, other.version_str)

  @staticmethod
  def php_slices_compare(a_split: List[str], b_split: List[str]):
    """
    Compare php versions after being split by '.'
    """
    for a, b in zip(a_split, b_split):
      if a.isdecimal() and b.isdecimal():
        compare = int(a) - int(b)
      elif not a.isdecimal() and not b.isdecimal():
        compare = PackagistVersion.compare_special_versions(a, b)
      elif a.isdecimal():
        compare = PackagistVersion.compare_special_versions('#', b)
      else:
        compare = PackagistVersion.compare_special_versions(a, '#')

      if compare != 0:
        if compare > 0:
          return 1
        return -1

    if len(a_split) > len(b_split):
      next_char = a_split[len(b_split)]
      if next_char.isdecimal():
        return 1
      return PackagistVersion.php_slices_compare(a_split[len(b_split):], ['#'])

    if len(a_split) < len(b_split):
      next_char = b_split[len(a_split)]
      if next_char.isdecimal():
        return -1
      return PackagistVersion.php_slices_compare(['#'], b_split[len(a_split):])

    return 0

  @staticmethod
  def php_version_compare(version_a: str, version_b: str) -> int:
    """
    Given two php versions, compare which is newer

    :return: 1 if a > b, -1 if b > a, 0 if a == b
    """
    version_a = PackagistVersion.php_canonicalize_version(version_a)
    version_b = PackagistVersion.php_canonicalize_version(version_b)

    a_split = version_a.split('.')
    b_split = version_b.split('.')
    return PackagistVersion.php_slices_compare(a_split, b_split)

  @staticmethod
  def php_canonicalize_version(version: str) -> str:
    """
    Replaces special separators (`-`,`_`,`+`) with `.`, and inserts `.`
    between any digit and non-digit.
    """
    if version.startswith('v'):
      version = version[1:]
    replaced = re.sub('[-_+]', '.', version)
    replaced = re.sub(r'([^\d.])(\d)', r'\1.\2', replaced)
    replaced = re.sub(r'(\d)([^\d.])', r'\1.\2', replaced)
    return replaced

  SPECIAL_CHARACTER_ORDER = {
      "dev": 0,
      "alpha": 1,
      "a": 1,
      "beta": 2,
      "b": 2,
      "RC": 3,
      "rc": 3,
      "#": 4,
      "pl": 5,
      "p": 5,
      None: 0,
  }

  @staticmethod
  def compare_special_versions(version_part_a: str, version_part_b: str) -> int:
    # pylint: disable=line-too-long
    """
    Compares the order of special characters against the order specified in php
    docs.

    any string not found in this list < dev < alpha = a < beta = b < RC = rc < # < pl = p.

    :return: 1 if a > b, -1 if b > a, 0 if a == b
    """
    # pylint: enable=line-too-long
    # This isn't quite the behaviour of the c implementation of php
    # version_compare
    # In php if the part starts with special_chars its enough.
    # ### For example:
    # *PHP implementation:*
    # `1.0.0beta1 = 1.0.0betawithsomeothertext1`
    #
    # *This python implementation*
    # `1.0.0beta1 > 1.0.0betawithsomeothertext1`
    # Because "any string not found in this list" should apply to
    # `betawithsomeothertext`
    found_a = PackagistVersion.SPECIAL_CHARACTER_ORDER.get(version_part_a, -1)
    found_b = PackagistVersion.SPECIAL_CHARACTER_ORDER.get(version_part_b, -1)

    if found_a > found_b:
      return 1
    if found_a < found_b:
      return -1
    return 0


class Packagist(EnumerableEcosystem):
  """Packagist ecosystem"""

  _API_PACKAGE_URL = 'https://repo.packagist.org/p2/{package}.json'

  def _sort_key(self, version):
    return PackagistVersion(version)

  def coarse_version(self, version):
    """Coarse version.

    Treats version as integers separated by ., -, _, or +.
    Treats 'p'/'pl' suffixes as MAX_INT to ensure they sort after base versions
    (e.g. 1.0 < 1.0-p1).
    """
    if version.startswith('v'):
      version = version[1:]
    # Cannot use coarse_version_generic because 'p' and 'pl' are considered
    # greater than numbers
    # 0 > .1 (but 0.1 == 0..1)
    if not version or version[0] in '-_+.':
      return '00:00000000.00000000.00000000'
    # Split on separators.
    parts = re.split(r'[-_+.]', version)
    # Split on transitions between digits and non-digits
    parts = [p for part in parts for p in re.findall(r'^$|\d+|\D+', part)]
    # Filter empty parts
    parts = [p for p in parts if p]
    # Extract up to 3 integer components
    components = []
    overflow = False
    for p in parts[:3]:
      if p in ('p', 'pl'):
        val = 99999999999  # trigger overflow
      elif not p.isdecimal():
        break
      else:
        val = int(p)
      if val > 99999999:
        val = 99999999
        overflow = True
      components.append(val)
      if overflow:
        break

    # Pad with zeros to ensure 3 components
    # If we overflowed, we should pad with MAX instead of 0
    pad_value = 99999999 if overflow else 0
    while len(components) < 3:
      components.append(pad_value)

    return f'00:{components[0]:08d}.{components[1]:08d}.{components[2]:08d}'

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    url = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper = RequestHelper(config.shared_cache)
    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError('Failed to get Packagist versions for '
                         f'{package} with: {ex.response.text}') from ex

    response = json.loads(text_response)
    versions: list[str] = [x['version'] for x in response['packages'][package]]
    self.sort_versions(versions)
    # TODO(rexpan): Potentially filter out branch versions like dev-master

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)
