#
# Copyright (c) nexB Inc. and others.
# SPDX-License-Identifier: Apache-2.0
#
# Visit https://aboutcode.org and https://github.com/nexB/univers for support and download.

from __future__ import annotations
from typing import Any

def remove_spaces(string: str) -> str:
  return "".join(string.split())


def cmp(x: Any, y: Any) -> int:
  """
    Replacement for built-in Python 2 function cmp that was removed in Python 3
    From https://docs.python.org/2/library/functions.html?highlight=cmp#cmp :

        Compare the two objects x and y and return an integer according to the
        outcome. The return value is negative if x < y, zero if x == y and
        strictly positive if x > y.
    """
  # Type checking for None should come before equality to handle cases where
  # x or y might not support direct comparison with None if __eq__ is overridden.
  if x is None and y is None:
    return 0
  if x is None: # y is not None
    return -1
  if y is None: # x is not None
    return 1

  # Now that None cases are handled, proceed with comparisons.
  # This relies on x and y supporting __eq__, __gt__, __lt__.
  # If they don't, a TypeError will be raised, which is standard for cmp-like functions.
  if x == y:
    return 0

  # The (x > y) - (x < y) trick works because True is 1 and False is 0 in arithmetic.
  # If x > y:  1 - 0 = 1
  # If x < y:  0 - 1 = -1
  # If x == y (already handled) or incomparable in a way that both > and < are false,
  # this would yield 0 - 0 = 0. This is fine if equality is already checked.
  try:
    return (x > y) - (x < y)
  except TypeError:
    # Handle incomparable types if necessary, or let TypeError propagate.
    # For a generic cmp, propagating TypeError for incomparable types is standard.
    # Fallback to comparing type names if types are different and incomparable.
    # This is a more robust cmp implementation detail, but original was simpler.
    # Sticking to minimal replacement for now.
    # If one is number and other is string, Python 3 raises TypeError.
    # Python 2 cmp had arbitrary but consistent ordering for different types.
    # The (x > y) - (x < y) might raise TypeError for mixed types in Python 3.
    # For example, int > str will raise TypeError.
    # The original function's "else" implies x and y are comparable if not None and not equal.
    # This is fine. The type hints `Any` reflect this.
    raise # Re-raise the TypeError if comparison operators are not supported.
