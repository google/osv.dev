"""Maven version parser."""
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
import collections
import re

# pylint: disable=line-too-long
# Maven's very complicated spec:
# http://maven.apache.org/pom.html#Dependency_Version_Requirement_Specification

_TO_TRIM = ('0', '', 'final', 'ga')
_KEYWORD_ORDER = ('alpha', 'beta', 'milestone', 'rc', 'snapshot', '', 'sp')


def qualifier_order(token):
  """Returns an integer representing a token's order."""
  # ".qualifier" < "-qualifier" < "-number" < ".number"
  if token.value.isdigit():
    if token.prefix == '-':
      return 2

    assert token.prefix == '.'
    return 3

  if token.prefix == '-':
    return 1

  assert token.prefix == '.'
  return 0


class VersionToken(
    collections.namedtuple(
        'VersionToken', 'prefix value is_null', defaults=(False,))):
  """Version token."""

  __slots__ = ()

  def __eq__(self, other):
    return self.prefix == other.prefix and self.value == other.value

  def __lt__(self, other):
    if self.prefix == other.prefix:
      # if the prefix is the same, then compare the token:
      if self.value.isdigit() and other.value.isdigit():
        # Numeric tokens have the natural order.
        return int(self.value) < int(other.value)
      # The spec is unclear, but according to Maven's implementation, numerics
      # sort after non-numerics, **unless it's a null value**.
      # https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L443
      if self.value.isdigit() and not self.is_null:
        return False

      if other.value.isdigit() and not other.is_null:
        return True

      # Non-numeric tokens ("qualifiers") have the alphabetical order, except
      # for the following tokens which come first in _KEYWORD_ORDER.
      #
      # The spec is unclear, but according to Maven's implementation, unknown
      # qualifiers sort after known qualifiers:
      # https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L423
      try:
        left_idx = _KEYWORD_ORDER.index(self.value)
      except ValueError:
        left_idx = len(_KEYWORD_ORDER)

      try:
        right_idx = _KEYWORD_ORDER.index(other.value)
      except ValueError:
        right_idx = len(_KEYWORD_ORDER)

      if left_idx == len(_KEYWORD_ORDER) and right_idx == len(_KEYWORD_ORDER):
        # Both are unknown qualifiers. Just do a lexical comparison.
        return self.value < other.value

      return left_idx < right_idx

    # else ".qualifier" < "-qualifier" < "-number" < ".number"
    return qualifier_order(self) < qualifier_order(other)


class Version:
  """Maven version."""

  def __init__(self):
    self.tokens = []

  def __str__(self):
    result = ''
    for token in self.tokens:
      result += token.prefix + token.value

    return result

  def __eq__(self, other):
    return self.tokens == other.tokens

  def __lt__(self, other):
    for i in range(max(len(self.tokens), len(other.tokens))):
      # the shorter one padded with enough "null" values with matching prefix to
      # have the same length as the longer one. Padded "null" values depend on
      # the prefix of the other version: 0 for '.', "" for '-'
      if i >= len(self.tokens):
        if other.tokens[i].prefix == '.':
          left = VersionToken('.', '0', is_null=True)
        else:
          assert other.tokens[i].prefix == '-'
          left = VersionToken('-', '', is_null=True)
      else:
        left = self.tokens[i]

      if i >= len(other.tokens):
        if self.tokens[i].prefix == '.':
          right = VersionToken('.', '0', is_null=True)
        else:
          assert self.tokens[i].prefix == '-'
          right = VersionToken('-', '', is_null=True)
      else:
        right = other.tokens[i]

      if left == right:
        continue

      return left < right

  @classmethod
  def from_string(cls, str_version):
    """Parse a version."""
    version = Version()

    # The Maven coordinate is split in tokens between dots ('.'), hyphens ('-')
    # and transitions between digits and characters. The prefix is recorded
    # and will have effect on the order.

    # Split and keep the delimiter.
    tokens = re.split(r'([-.])', str_version)
    for i in range(0, len(tokens), 2):
      if i == 0:
        # First token has no preceding prefix.
        prefix = ''
      else:
        # Preceding prefix.
        prefix = tokens[i - 1]

      # A transition between digits and characters is equivalent to a hyphen.
      # According to Maven's implementation: any non-digit is a "character":
      # https://github.com/apache/maven/blob/965aaa53da5c2d814e94a41d37142d0d6830375d/maven-artifact/src/main/java/org/apache/maven/artifact/versioning/ComparableVersion.java#L627

      # Find instances of <digit><non-digit> or <non-digit><digit>.
      # ?= makes the regex non-consuming (needed to catch overlapping
      # transitions such as <digit><non-digit><digit>).
      # This gives an array of indices where each index is where a hyphen should be.
      transitions = [
          m.span()[0] + 1
          for m in re.finditer(r'(?=(\d[^\d]|[^\d]\d))', tokens[i])
      ]
      # Add the last index so that our algorithm to split up the current token works.
      transitions.append(len(tokens[i]))

      prev_index = 0
      for j, transition in enumerate(transitions):
        if j > 0:
          prefix = '-'

        # The spec doesn't say this, but all qualifiers are case insensitive.
        current = tokens[i][prev_index:transition].lower()
        if not current:
          # Empty tokens are replaced with "0".
          current = '0'

        # Normalize "cr" to "rc" for easier comparison since they are equal in
        # precedence.
        if current == 'cr':
          current = 'rc'

        # Also do this for 'ga', 'final' which are equivalent to empty string.
        # "release" is not part of the spec but is implemented by Maven.
        if current in ('ga', 'final', 'release'):
          current = ''

        # the "alpha", "beta" and "milestone" qualifiers can respectively be
        # shortened to "a", "b" and "m" when directly followed by a number.
        if transition != len(tokens[i]):
          if current == 'a':
            current = 'alpha'

          if current == 'b':
            current = 'beta'

          if current == 'm':
            current = 'milestone'

        if current.isdigit():
          # Remove any leading zeros.
          current = str(int(current))

        version.tokens.append(VersionToken(prefix, current))
        prev_index = transition

    # Then, starting from the end of the version, the trailing "null" values
    # (0, "", "final", "ga") are trimmed.
    i = len(version.tokens) - 1
    while i >= 0:
      if version.tokens[i].value in _TO_TRIM:
        version.tokens.pop(i)
        i -= 1
        continue

      # This process is repeated at each remaining hyphen from end to start.
      while i >= 0 and version.tokens[i].prefix != '-':
        i -= 1

      i -= 1

    return version
