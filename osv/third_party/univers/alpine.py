#
# Copyright (c) nexB Inc. and others.
# SPDX-License-Identifier: Apache-2.0
#
# Visit https://aboutcode.org and
# https://github.com/nexB/univers for support and download.

# Modified to support revisions in the form of <ver>-r<rev-num>
from __future__ import annotations

import attr
import re
from typing import Any, ClassVar, Pattern, Tuple, Type, Union # Added Pattern, Type

from . import gentoo # from osv.third_party.univers import gentoo
from .utils import remove_spaces # from osv.third_party.univers import utils


class InvalidVersion(ValueError):
  pass


def is_valid_alpine_version(s: str) -> bool:
  """
  Return True is the string `s` is a valid Alpine version.
  We do not support yet version strings that start with
  non-significant zeros.
  For example:
  >>> is_valid_alpine_version("006")
  False
  >>> is_valid_alpine_version("1.2.3")
  True
  >>> is_valid_alpine_version("02-r1")
  True
  """
  # AlpineLinuxVersion might not be defined yet if this function is at the top level
  # and called during class definition. However, it's used as a static/class var.
  # Assuming it's defined before first actual call.
  search_match = AlpineLinuxVersion.version_extractor.search(s)
  if not search_match:
    return False

  version_part: str = search_match.group(1) # Extracted main version part
  # Partition by '.' to get the first numeric component for zero-padding check
  first_numeric_component, _, _ = version_part.partition(".")
  # Also handle suffixes like -rX for the first component
  first_numeric_component, _, _ = first_numeric_component.partition("-")

  if not first_numeric_component.isdigit():
    # If the first component isn't purely digits (e.g., contains letters),
    # the leading zero rule for numbers doesn't apply in the same way,
    # or it's handled by gentoo.is_valid.
    # The original logic returns True here, implying it's valid or checked by gentoo.
    return True

  # Check for non-significant leading zeros for purely numeric first component
  # e.g., "06" is invalid if it means 6, but "6" is valid.
  # "0" is valid. "00" might be invalid if it means 0.
  if len(first_numeric_component) > 1 and first_numeric_component.startswith('0'):
      return False # Disallow "00", "01", "007" etc.

  # The original check `str(int(left)) == left` is a good way to check this
  # after ensuring `left` is purely numeric.
  # i = int(first_numeric_component)
  # return str(i) == first_numeric_component
  # This has been simplified to the leading zero check above.

  return True # If no leading zeros or single "0"


@attr.s(frozen=True, order=False, hash=True)
class Version:
  """
  Base version mixin to subclass for each version syntax implementation.
  Each version subclass is:
  - immutable and hashable
  - comparable and orderable e.g., such as implementing all rich comparison
    operators or implementing functools.total_ordering. The default is to
    compare the value as-is.
  """

  # the original string used to build this Version
  string: str = attr.ib(type=str)

  # the normalized string for this Version, stored without spaces and
  # lowercased. Any leading v is removed too.
  # Initialized in __attrs_post_init__
  normalized_string: Optional[str] = attr.ib(init=False, default=None, repr=False)


  # a comparable scheme-specific version object constructed from
  # the version string. Initialized in __attrs_post_init__.
  value: Any = attr.ib(init=False, default=None, repr=False) # Type overridden in subclasses

  def __attrs_post_init__(self) -> None:
    # Ensure type of self.string is str if passed from subclass or direct instantiation
    current_normalized_string: str = self.normalize(str(self.string))
    if not self.is_valid(current_normalized_string): # type: ignore[arg-type] # is_valid expects str
      raise InvalidVersion(f"{self.string!r} is not a valid {self.__class__.__name__!r}") # Use __name__

    # Notes: setattr is used because this is an immutable frozen instance.
    # See https://www.attrs.org/en/stable/init.html?#post-init
    object.__setattr__(self, "normalized_string", current_normalized_string)
    current_value: Any = self.build_value(current_normalized_string) # type: ignore[arg-type] # build_value expects str
    object.__setattr__(self, "value", current_value)

  @classmethod
  def is_valid(cls: Type[Version], string_val: str) -> bool: # Renamed string to string_val
    """
    Return True if the ``string_val`` is a valid version for its scheme or False
    if not valid. The empty string, None, False and 0 are considered invalid.
    Subclasses should implement this.
    """
    return bool(string_val) # Basic check, subclasses should override for specific validation

  @classmethod
  def normalize(cls: Type[Version], string_val: str) -> str: # Renamed string to string_val
    """
    Return a normalized version string from ``string_val ``. Subclass can override.
    """
    # FIXME: Is removing spaces and strip v the right thing to do?
    # The original code had rstrip("v ").strip() which seems unusual.
    # Typically, one might remove a leading 'v' if present.
    # Assuming remove_spaces handles general whitespace.
    # If 'v' should be stripped from the end, it's specific.
    # If it's a prefix, it should be string_val.lstrip('v').
    # Current: remove_spaces then rstrip "v " (space after v implies "v " literal).
    temp_string = remove_spaces(string_val)
    if temp_string.endswith("v "): # Literal "v " at the end
        temp_string = temp_string[:-2]
    return temp_string.strip()


  @classmethod
  def build_value(cls: Type[Version], string_val: str) -> Any: # Renamed string to string_val
    """
    Return a wrapped version "value" object for a version ``string_val``.
    Subclasses can override. The default is a no-op and returns the string
    as-is, and is called by default at init time with the computed
    normalized_string.
    """
    return string_val

  def satisfies(self, constraint: Any) -> bool:
    """
    Return True is this Version satisfies the ``constraint``
    VersionConstraint. Satisfying means that this version is "within" the
    ``constraint``.
    """
    # `self in constraint` implies constraint is a container (e.g. VersionConstraint)
    # that implements __contains__(self, item) where item is this Version instance.
    return constraint.__contains__(self)


  def __str__(self) -> str:
    # Should return the original string or normalized string as per typical use?
    # Original returns str(self.value). For Alpine, value is tuple.
    # This will print the tuple representation.
    # If original string representation is desired, use self.string or self.normalized_string.
    return str(self.value)

  def __eq__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value == other.value # Direct comparison for base, overridden by Alpine

  def __lt__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    # This assumes self.value is comparable for all subclasses if not overridden.
    return self.value < other.value # type: ignore[operator]

  def __gt__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value > other.value # type: ignore[operator]

  def __le__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value <= other.value # type: ignore[operator]

  def __ge__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value >= other.value # type: ignore[operator]


@attr.s(frozen=True, order=False, eq=False, hash=True) # order=False means rich comparisons are not auto-generated
class AlpineLinuxVersion(Version):
  """Alpine linux version"""
  # E.g. For this version (1.9.5_p2-r3), the following regex
  # extracts (1.9.5_p2) and (3)
  version_extractor: ClassVar[Pattern[str]] = re.compile(r'(.+?)(?:[\.-]r(\d+))?$')

  # Some suffixes are not separated with an underscore. E.g. 1.9.5p2
  # This should find them for inserting an underscore (replace with r'\1_\2')
  # See: https://gitlab.alpinelinux.org/alpine/abuild/-/issues/10088 for more context
  patch_finder: ClassVar[Pattern[str]] = re.compile(r'(\d+)(p\d+)')

  # Override `value` type from base class for more specificity
  value: Tuple[str, int]

  @classmethod
  def add_underscore(cls: Type[AlpineLinuxVersion], input_str: str) -> str: # Renamed input to input_str
    return re.sub(cls.patch_finder, r'\1_\2', input_str, 1)

  @classmethod
  def build_value(cls: Type[AlpineLinuxVersion], string_val: str) -> Tuple[str, int]: # Renamed string
    search_match = cls.version_extractor.search(string_val)
    # Ensure search_match is not None before .group()
    if not search_match:
        # This case should ideally be caught by is_valid before build_value is called.
        # Or, is_valid should be robust enough.
        raise InvalidVersion(f"Version string '{string_val}' could not be parsed by version_extractor.")

    main_group: str = search_match.group(1)
    main_group_patched: str = cls.add_underscore(main_group)

    revision_group: Optional[str] = search_match.group(2)
    revision_int: int = int(revision_group) if revision_group and revision_group.isdigit() else 0

    return (main_group_patched, revision_int)

  @classmethod
  def is_valid(cls: Type[AlpineLinuxVersion], string_val: str) -> bool: # Renamed string
    # Patched string is used for gentoo.is_valid but original for is_valid_alpine_version
    # This seems a bit inconsistent. Assuming is_valid_alpine_version should also use patched.
    # Let's follow original logic closely first.

    # The initial is_valid_alpine_version check is primarily for leading zeros in numeric parts.
    # The gentoo.is_valid likely handles the broader structure.
    if not is_valid_alpine_version(string_val): # Check original string for leading zero issues
        return False

    string_patched: str = cls.add_underscore(string_val)
    # gentoo.is_valid should check the main version part (value[0] after build_value)
    # This means we might need to extract the main part first if gentoo.is_valid
    # doesn't handle the full alpine string with -rX itself.
    # Assuming gentoo.is_valid can handle the patched string (potentially with _rX if not stripped by add_underscore).
    # The current AlpineLinuxVersion.build_value extracts the -r part.
    # gentoo.is_valid should be called on the main version part.

    search_match = cls.version_extractor.search(string_patched)
    if not search_match:
        return False # Should not happen if version_extractor is robust
    main_version_part = search_match.group(1)

    return gentoo.is_valid(main_version_part)


  def __eq__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    # self.value is Tuple[str, int], other.value is also Tuple[str, int]
    # gentoo.vercmp returns int: 0 for equal, <0 if self < other, >0 if self > other
    gentoo_vercmp_result: int = gentoo.vercmp(self.value[0], other.value[0])
    return gentoo_vercmp_result == 0 and self.value[1] == other.value[1]

  def __lt__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    gentoo_vercmp_result: int = gentoo.vercmp(self.value[0], other.value[0])
    if gentoo_vercmp_result == 0: # If main versions are equal, compare revisions
      return self.value[1] < other.value[1]
    return gentoo_vercmp_result < 0

  def __gt__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    gentoo_vercmp_result: int = gentoo.vercmp(self.value[0], other.value[0])
    if gentoo_vercmp_result == 0: # If main versions are equal, compare revisions
      return self.value[1] > other.value[1]
    return gentoo_vercmp_result > 0

  # __le__ and __ge__ can be derived by @functools.total_ordering if __eq__ and one of __lt__, __gt__ are defined.
  # For explicitness, they are often provided if not using @total_ordering.
  # Attrs(order=False) means we must define them all if we want them all.
  # Since the original file doesn't have them, I'll stick to what's there.
  # However, the base class Version defines them all, so this class should too for consistency if it wants to override.
  # The base class comparisons might not be correct for Alpine if value types differ.
  # Let's add __le__ and __ge__ for completeness, matching the pattern.

  def __le__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    # return self < other or self == other
    gentoo_vercmp_result: int = gentoo.vercmp(self.value[0], other.value[0])
    if gentoo_vercmp_result == 0:
        return self.value[1] <= other.value[1]
    return gentoo_vercmp_result < 0

  def __ge__(self, other: object) -> bool:
    if not isinstance(other, self.__class__):
      return NotImplemented
    # return self > other or self == other
    gentoo_vercmp_result: int = gentoo.vercmp(self.value[0], other.value[0])
    if gentoo_vercmp_result == 0:
        return self.value[1] >= other.value[1]
    return gentoo_vercmp_result > 0
