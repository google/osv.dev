#
# Copyright (c) nexB Inc. and others.
# Extracted from http://nexb.com and https://github.com/nexB/debian_inspector/
# Copyright (c) Peter Odding
# Author: Peter Odding <peter@peterodding.com>
# URL: https://github.com/xolox/python-deb-pkg-tools
# SPDX-License-Identifier: MIT
#
# Visit https://aboutcode.org and https://github.com/nexB/univers for support and download.

import logging
import operator as operator_module
import re
from functools import cmp_to_key
from itertools import zip_longest

from attr import asdict
from attr import attrs
from attr import attrib

logger = logging.getLogger(__name__)

"""
Parse, compare and sort Debian package versions.

This module is an implementation of the version comparison and sorting algorithm
described at
https://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version

This has been substantially modified and enhanced from the original 
python-deb-pkg-tools by Peter Odding to extract only the subset that
does the version parsing, comparison and version constraints evaluation.



Some examples:

#### Compare two arbitrary version strings

    >>> from univers.debian import compare_versions
    >>> compare_versions('0:1.0-test1', '0:1.0-test2')
    -1
    >>> compare_versions('1.0', '0.6')
    1
    >>> compare_versions('2:1.0', '1:1.0')
    -1

#### Use Version as a key function to sort a list of version strings

    >>> from univers.debian import Version
    >>> sorted(['0:1.0-test1', '1:0.0-test0', '0:1.0-test2'] , key=Version.from_string)
    ['0:1.0-test1', '0:1.0-test2', '1:0.0-test0']

"""


@attrs(eq=False, order=False, frozen=True, hash=False, slots=True, str=False)
class Version(object):
    """
    Rich comparison of Debian package versions as first-class Python objects.

    The :class:`Version` class is a subclass of the built in :class:`str` type
    that implements rich comparison according to the version sorting order
    defined in the Debian Policy Manual. Use it to sort Debian package versions
    from oldest to newest in ascending version order like this:

      >>> from univers.debian import Version
      >>> unsorted = ['0.1', '0.5', '1.0', '2.0', '3.0', '1:0.4', '2:0.3']
      >>> print([str(v) for v in sorted(Version.from_string(s) for s in unsorted)])
      ['0.1', '0.5', '1.0', '2.0', '3.0', '1:0.4', '2:0.3']

      We also accept trailing punctuations in the version and release:

      >>> v = "2:4.13.1-0ubuntu0.16.04.1.1~"
      >>> assert str(Version.from_string(v)) == v
      >>> v = "2:4.13.1~"
      >>> assert str(Version.from_string(v)) == v

    This example uses 'epoch' numbers (the numbers before the colons) to
    demonstrate that this version sorting order is different from regular
    sorting and 'natural order sorting'.
    """

    epoch = attrib(default=0)
    upstream = attrib(default=None)
    revision = attrib(default="0")

    def __str__(self, *args, **kwargs):
        if self.epoch:
            version = f"{self.epoch}:{self.upstream}"
        else:
            version = f"{self.upstream}"

        if self.revision not in (None, "0"):
            version += f"-{self.revision}"

        return version

    def __repr__(self, *args, **kwargs):
        return str(self)

    def __hash__(self):
        return hash(self.tuple())

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.tuple() == other.tuple()

    def __ne__(self, other):
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, "<<", other)

    def __le__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, "<=", other)

    def __gt__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, ">>", other)

    def __ge__(self, other):
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, ">=", other)

    @classmethod
    def from_string(cls, version):
        if not version and not isinstance(version, str):
            raise ValueError('Invalid version string: "{}"'.format(version))
        version = version.strip()
        if not version:
            raise ValueError('Invalid version string: "{}"'.format(version))
        if not cls.is_valid(version):
            raise ValueError('Invalid version string: "{}"'.format(version))

        if ":" in version:
            epoch, _, version = version.partition(":")
            epoch = int(epoch)
        else:
            epoch = 0

        if "-" in version:
            upstream, _, revision = version.rpartition("-")
        else:
            upstream = version
            revision = "0"
        return cls(epoch=epoch, upstream=upstream, revision=revision)

    @classmethod
    def is_valid(cls, version):
        return is_valid_debian_version(version)

    def compare(self, other_version):
        return compare_versions(self, other_version)

    def to_dict(self):
        return asdict(self)

    def tuple(self):
        return self.epoch, self.upstream, self.revision


is_valid_debian_version = re.compile(
    r"^"
    # epoch must start with a digit
    r"(\d+:)?"
    # upstream must start with a digit
    r"\d"
    r"("
    # upstream  can contain only alphanumerics and the characters . + -
    # ~ (full stop, plus, hyphen, tilde)
    r"[A-Za-z0-9\.\+\~\-]+"
    r"|"
    # If there is no debian_revision then hyphens are not allowed in version.
    r"[A-Za-z0-9\.\+\~]+-[A-Za-z0-9\+\.\~]+"
    r")?"
    r"$"
).match


def eval_constraint(version1, operator, version2):
    """
    Evaluate a versions constraint where two Debian package versions are
    compared with an operator such as < or >. Return True if the constraint is
    satisfied and False otherwise.
    """

    version1 = coerce_version(version1)
    version2 = coerce_version(version2)

    result = compare_versions(version1, version2)
    # See https://www.debian.org/doc/debian-policy/ch-relationships.html#syntax-of-relationship-fields
    operators = {
        "<<": operator_module.lt,
        "<=": operator_module.le,
        "=": operator_module.eq,
        ">=": operator_module.ge,
        ">>": operator_module.gt,
        # legacy for compat
        "<": operator_module.lt,
        ">": operator_module.gt,
    }

    try:
        operator = operators[operator]
    except KeyError:
        msg = f"Unsupported Debian version constraint comparison operator: {version1} {operator} {version2}"
        raise ValueError(msg)
    return operator(result, 0)


def compare_versions_key(x):
    """
    Return a key version function suitable for use in sorted().
    """
    return cmp_to_key(compare_versions)(x)


def compare_strings_key(x):
    """
    Return a key string function suitable for use in sorted().
    """
    return cmp_to_key(compare_strings)(x)


def compare_strings(version1, version2):
    """
    Compare two version strings (upstream or revision) using Debian semantics
    and return one of the following integer numbers:
        - -1 means version1 sorts before version2
        - 0 means version1 and version2 are equal
        - 1 means version1 sorts after version2
    """
    logger.debug("Comparing Debian version number substrings %r and %r ..", version1, version2)
    mapping = characters_order
    v1 = list(version1)
    v2 = list(version2)
    while v1 or v2:
        # Quoting from the 'deb-version' manual page: First the initial part of each
        # string consisting entirely of non-digit characters is determined. These two
        # parts (one of which may be empty) are compared lexically. If a difference is
        # found it is returned. The lexical comparison is a comparison of ASCII values
        # modified so that all the letters sort earlier than all the non-letters and so
        # that a tilde sorts before anything, even the end of a part. For example, the
        # following parts are in sorted order: '~~', '~~a', '~', the empty part, 'a'.
        p1 = get_non_digit_prefix(v1)
        p2 = get_non_digit_prefix(v2)
        if p1 != p2:
            logger.debug("Comparing non-digit prefixes %r and %r ..", p1, p2)
            for c1, c2 in zip_longest(p1, p2, fillvalue=""):
                logger.debug(
                    "Performing lexical comparison between characters %r and %r ..", c1, c2
                )
                o1 = mapping.get(c1)
                o2 = mapping.get(c2)
                if o1 < o2:
                    logger.debug(
                        "Determined that %r sorts before %r (based on lexical comparison).",
                        version1,
                        version2,
                    )
                    return -1
                elif o1 > o2:
                    logger.debug(
                        "Determined that %r sorts after %r (based on lexical comparison).",
                        version1,
                        version2,
                    )
                    return 1
        elif p1:
            logger.debug("Skipping matching non-digit prefix %r ..", p1)
        # Quoting from the 'deb-version' manual page: Then the initial part of the
        # remainder of each string which consists entirely of digit characters is
        # determined. The numerical values of these two parts are compared, and any
        # difference found is returned as the result of the comparison. For these purposes
        # an empty string (which can only occur at the end of one or both version strings
        # being compared) counts as zero.
        d1 = get_digit_prefix(v1)
        d2 = get_digit_prefix(v2)
        logger.debug("Comparing numeric prefixes %i and %i ..", d1, d2)
        if d1 < d2:
            logger.debug(
                "Determined that %r sorts before %r (based on numeric comparison).",
                version1,
                version2,
            )
            return -1
        elif d1 > d2:
            logger.debug(
                "Determined that %r sorts after %r (based on numeric comparison).",
                version1,
                version2,
            )
            return 1
        else:
            logger.debug("Determined that numeric prefixes match.")
    logger.debug("Determined that version numbers are equal.")
    return 0


def compare_versions(version1, version2):
    """
    Compare two Version objects or strings and return one of the following
    integer numbers:

      - -1 means version1 sorts before version2
      - 0 means version1 and version2 are equal
      - 1 means version1 sorts after version2
    """
    version1 = coerce_version(version1)
    version2 = coerce_version(version2)
    return compare_version_objects(version1, version2)


def coerce_version(value):
    """
    Return a Version object from value.

    :param value: The value to coerce (a string or :class:`Version` object).
    :returns: A :class:`Version` object.
    """
    if not isinstance(value, Version):
        value = Version.from_string(value)
    return value


def compare_version_objects(version1, version2):
    """
    Compare two Version objects and return one of the following
    integer numbers:

      - -1 means version1 sorts before version2
      - 0 means version1 and version2 are equal
      - 1 means version1 sorts after version2
    """
    if version1.epoch < version2.epoch:
        return -1
    if version1.epoch > version2.epoch:
        return 1
    result = compare_strings(version1.upstream, version2.upstream)
    if result != 0:
        return result
    if version1.revision or version2.revision:
        return compare_strings(version1.revision, version2.revision)
    return 0


def get_digit_prefix(characters):
    """
    Return the digit prefix from a list of characters.
    """
    value = 0
    while characters and characters[0].isdigit():
        value = value * 10 + int(characters.pop(0))
    return value


def get_non_digit_prefix(characters):
    """
    Return the non-digit prefix from a list of characters.
    """
    prefix = []
    while characters and not characters[0].isdigit():
        prefix.append(characters.pop(0))
    return prefix


# a mapping of characters to integers representing the Debian sort order.
characters_order = {
    # The tilde sorts before everything.
    "~": 0,
    # The empty string sort before everything except a tilde.
    "": 1,
    # Letters sort before everything but a tilde or empty string, in their regular lexical sort order.
    "A": 2,
    "B": 3,
    "C": 4,
    "D": 5,
    "E": 6,
    "F": 7,
    "G": 8,
    "H": 9,
    "I": 10,
    "J": 11,
    "K": 12,
    "L": 13,
    "M": 14,
    "N": 15,
    "O": 16,
    "P": 17,
    "Q": 18,
    "R": 19,
    "S": 20,
    "T": 21,
    "U": 22,
    "V": 23,
    "W": 24,
    "X": 25,
    "Y": 26,
    "Z": 27,
    "a": 28,
    "b": 29,
    "c": 30,
    "d": 31,
    "e": 32,
    "f": 33,
    "g": 34,
    "h": 35,
    "i": 36,
    "j": 37,
    "k": 38,
    "l": 39,
    "m": 40,
    "n": 41,
    "o": 42,
    "p": 43,
    "q": 44,
    "r": 45,
    "s": 46,
    "t": 47,
    "u": 48,
    "v": 49,
    "w": 50,
    "x": 51,
    "y": 52,
    "z": 53,
    # Punctuation characters follow in their regular lexical sort order.
    "+": 54,
    "-": 55,
    ".": 56,
}
