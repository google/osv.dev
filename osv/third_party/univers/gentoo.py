#
# Copyright (c) 2006-2019, pkgcore contributors
# SPDX-License-Identifier: BSD-3-Clause
# Version comparison utility extracted from pkgcore and further stripped down.
#
# Visit https://aboutcode.org and https://github.com/nexB/univers for support and download.

from __future__ import annotations

import re
from typing import Callable, Dict, List, Match, Optional, Pattern, Tuple # Added necessary types

from .utils import cmp # from osv.third_party.univers.utils import cmp
from .utils import remove_spaces # from osv.third_party.univers.utils import remove_spaces

# This is a method of a compiled regex object
_is_gentoo_version: Callable[[str], Optional[Match[str]]] = re.compile(
    r"^(?:\d+)(?:\.\d+)*[a-zA-Z]?(?:_(p(?:re)?|beta|alpha|rc)\d*)*$").match

suffix_regexp: Pattern[str] = re.compile(r"^(alpha|beta|rc|pre|p)(\d*)$")

revision_regexp: Pattern[str] = re.compile(r".*([\.-]r\d+)") # Group 1 captures e.g. "-r1" or ".r1"

suffix_value: Dict[str, int] = {"pre": -2, "p": 1, "alpha": -4, "beta": -3, "rc": -1}
"""
gentoo ebuild version comparison
"""


def is_valid(string_val: str) -> bool: # Renamed string to string_val
  # remove_spaces ensures string_val is processed without leading/trailing spaces
  # parse_version_and_revision extracts the main version part and revision.
  # _is_gentoo_version then validates only the main version part.
  version_part, _ = parse_version_and_revision(remove_spaces(string_val)) # Renamed version
  return bool(_is_gentoo_version(version_part)) # bool() converts Match object or None to boolean


def parse_version_and_revision(version_string: str) -> Tuple[str, int]:
  """
  Return a tuple of (version string part, revision int) given a ``version_string``.
  E.g., "1.2.3-r4" -> ("1.2.3", 4). "1.2.3" -> ("1.2.3", 0).
  """
  revision_val: int = 0 # Renamed revision
  version_part: str = version_string # Renamed version

  # Search for revision pattern (e.g., "-r1", ".r1")
  match_obj: Optional[Match[str]] = revision_regexp.search(version_string) # Renamed match
  if match_obj:
    # group(1) is like "-r1" or ".r1". We need the number part.
    # The first char is delimiter ('.' or '-'), second is 'r'. So number starts at index 2.
    revision_str: str = match_obj.group(1)[2:]
    if revision_str.isdigit(): # Ensure it's a number before int()
        revision_val = int(revision_str)
    else:
        # This case implies a malformed revision string, e.g., "1.2-rfoo"
        # Depending on strictness, could raise error or ignore.
        # Original code assumes int() will succeed.
        pass # Keep revision_val = 0 or handle error

    # The main version part is everything before the matched revision string.
    version_part = version_string[:match_obj.span(1)[0]]

  return version_part, revision_val


def vercmp(ver1_str: Optional[str], ver2_str: Optional[str]) -> int: # Renamed ver1, ver2
  """
  Compare two versions ``ver1`` and ``ver2`` and return 0, 1, or -1 according
  to the Python 2 cmp() semantics:

      Compare the two objects x and y and return an integer according to the
      outcome. The return value is negative if x < y, zero if x == y and
      strictly positive if x > y.
  """
  if not ver1:
    if not ver2:
      return 0
    else:
      return -1
  elif not ver2:
    return 1

  ver1, rev1 = parse_version_and_revision(ver1)
  ver2, rev2 = parse_version_and_revision(ver2)

  # If the versions are the same, comparing revisions will suffice.
  if ver1 == ver2:
    # revisions are equal if 0 or None (versionless cpv)
    if not rev1 and not rev2:
      return 0
    return cmp(rev1, rev2)

  # Split up the versions into dotted strings and lists of suffixes.
  parts1 = ver1.split("_")
  parts2 = ver2.split("_")

  # If the dotted strings are equal, we can skip doing a detailed comparison.
  if parts1[0] != parts2[0]:

    # First split up the dotted strings into their components.
    ver_parts1 = parts1[0].split(".")
    ver_parts2 = parts2[0].split(".")

    # Pull out any letter suffix on the final components and keep
    # them for later.
    letters = []
    for ver_parts in (ver_parts1, ver_parts2):
      if ver_parts[-1][-1].isalpha():
        letters.append(ord(ver_parts[-1][-1]))
        ver_parts[-1] = ver_parts[-1][:-1]
      else:
        # Using -1 simplifies comparisons later
        letters.append(-1)

    # OPT: Pull length calculation out of the loop
    ver_parts1_len = len(ver_parts1)
    ver_parts2_len = len(ver_parts2)

    # Iterate through the components
    for v1, v2 in zip(ver_parts1, ver_parts2):

      # If the string components are equal, the numerical
      # components will be equal too.
      if v1 == v2:
        continue

      # If one of the components begins with a "0" then they
      # are compared as floats so that 1.1 > 1.02; else ints.
      if v1[0] != "0" and v2[0] != "0":
        v1 = int(v1)
        v2 = int(v2)
      else:
        # handle the 0.060 == 0.060 case.
        v1 = v1.rstrip("0")
        v2 = v2.rstrip("0")

      # If they are not equal, the higher value wins.
      c = cmp(v1, v2)
      if c:
        return c

    if ver_parts1_len > ver_parts2_len:
      return 1
    elif ver_parts2_len > ver_parts1_len:
      return -1

    # The dotted components were equal. Let's compare any single
    # letter suffixes.
    if letters[0] != letters[1]:
      return cmp(letters[0], letters[1])

  # The dotted components were equal, so remove them from our lists
  # leaving only suffixes.
  del parts1[0]
  del parts2[0]

  # OPT: Pull length calculation out of the loop
  parts1_len = len(parts1)
  parts2_len = len(parts2)

  # Iterate through the suffixes
  for x in range(max(parts1_len, parts2_len)):

    # If we're at the end of one of our lists, we need to use
    # the next suffix from the other list to decide who wins.
    if x == parts1_len:
      match = suffix_regexp.match(parts2[x])
      val = suffix_value[match.group(1)]
      if val:
        return cmp(0, val)
      return cmp(0, int("0" + match.group(2)))
    if x == parts2_len:
      match = suffix_regexp.match(parts1[x])
      val = suffix_value[match.group(1)]
      if val:
        return cmp(val, 0)
      return cmp(int("0" + match.group(2)), 0)

    # If the string values are equal, no need to parse them.
    # Continue on to the next.
    if parts1[x] == parts2[x]:
      continue

    # Match against our regular expression to make a split between
    # "beta" and "1" in "beta1"
    match1 = suffix_regexp.match(parts1[x])
    match2 = suffix_regexp.match(parts2[x])

    # If our int'ified suffix names are different, use that as the basis
    # for comparison.
    c = cmp(suffix_value[match1.group(1)], suffix_value[match2.group(1)])
    if c:
      return c

    # Otherwise use the digit as the basis for comparison.
    c = cmp(int("0" + match1.group(2)), int("0" + match2.group(2)))
    if c:
      return c

  # Our versions had different strings but ended up being equal.
  # The revision holds the final difference.
  return cmp(rev1, rev2)
