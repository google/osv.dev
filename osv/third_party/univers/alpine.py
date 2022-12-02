#
# Copyright (c) nexB Inc. and others.
# SPDX-License-Identifier: Apache-2.0
#
# Visit https://aboutcode.org and
# https://github.com/nexB/univers for support and download.
import attr
import re

from . import gentoo
from .utils import remove_spaces


class InvalidVersion(ValueError):
  pass


def is_valid_alpine_version(s: str):
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
  False
  """
  search = AlpineLinuxVersion.version_extractor.search(s)
  if not search:
    return False
  
  s = search.group(1)
  left, _, _ = s.partition(".")
  # hanlde the suffix case
  left, _, _ = left.partition("-")
  if not left.isdigit():
    return True
  i = int(left)
  return str(i) == left


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
  string = attr.ib(type=str)

  # the normalized string for this Version, stored without spaces and
  # lowercased. Any leading v is removed too.
  normalized_string = attr.ib(type=str, default=None, repr=False)

  # a comparable scheme-specific version object constructed from
  # the version string
  value = attr.ib(default=None, repr=False, type=(str, int))

  def __attrs_post_init__(self):
    normalized_string = self.normalize(self.string)
    if not self.is_valid(normalized_string):
      raise InvalidVersion(f"{self.string!r} is not a valid {self.__class__!r}")

    # Set the normalized string as default value

    # Notes: setattr is used because this is an immutable frozen instance.
    # See https://www.attrs.org/en/stable/init.html?#post-init
    object.__setattr__(self, "normalized_string", normalized_string)
    value = self.build_value(normalized_string)
    object.__setattr__(self, "value", value)

  @classmethod
  def is_valid(cls, string):
    """
    Return True if the ``string`` is a valid version for its scheme or False
    if not valid. The empty string, None, False and 0 are considered invalid.
    Subclasses should implement this.
    """
    return bool(string)

  @classmethod
  def normalize(cls, string):
    """
    Return a normalized version string from ``string ``. Subclass can override.
    """
    # FIXME: Is removing spaces and strip v the right thing to do?
    return remove_spaces(string).rstrip("v ").strip()

  @classmethod
  def build_value(cls, string):
    """
    Return a wrapped version "value" object for a version ``string``.
    Subclasses can override. The default is a no-op and returns the string
    as-is, and is called by default at init time with the computed
    normalized_string.
    """
    return string

  def satisfies(self, constraint):
    """
    Return True is this Version satisfies the ``constraint``
    VersionConstraint. Satisfying means that this version is "within" the
    ``constraint``.
    """
    return self in constraint

  def __str__(self):
    return str(self.value)

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value.__eq__(other.value)

  def __lt__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value.__lt__(other.value)

  def __gt__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value.__gt__(other.value)

  def __le__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value.__le__(other.value)

  def __ge__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    return self.value.__ge__(other.value)


@attr.s(frozen=True, order=False, eq=False, hash=True)
class AlpineLinuxVersion(Version):
  """Alpine linux version"""
  # E.g. For this version (1.9.5p2-r3), the following regex
  # extracts (1.9.5p2) and (3)
  version_extractor = re.compile(r'(.+?)(?:-r(\d+))?$')
  
  @classmethod
  def build_value(cls, string: str):
    search = cls.version_extractor.search(string)
    return (search.group(1), int(search.group(2) or 0))


  @classmethod
  def is_valid(cls, string):
    return is_valid_alpine_version(string) and gentoo.is_valid(string)

  def __eq__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    gentoo_vercmp = gentoo.vercmp(self.value[0], other.value[0])
    return gentoo_vercmp == 0 and self.value[1] == other.value[1]

  def __lt__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented
    try:
      gentoo_vercmp = gentoo.vercmp(self.value[0], other.value[0])
    except IndexError:
      print("AYYET")
    if gentoo_vercmp == 0:
      return self.value[1] > other.value[1]

    return gentoo_vercmp < 0

  def __gt__(self, other):
    if not isinstance(other, self.__class__):
      return NotImplemented

    gentoo_vercmp = gentoo.vercmp(self.value[0], other.value[0])
    if gentoo_vercmp == 0:
      return self.value[1] < other.value[1]
    return gentoo_vercmp > 0
