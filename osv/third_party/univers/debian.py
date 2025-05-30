#
# Copyright (c) nexB Inc. and others.
# Extracted from http://nexb.com and https://github.com/nexB/debian_inspector/
# Copyright (c) Peter Odding
# Author: Peter Odding <peter@peterodding.com>
# URL: https://github.com/xolox/python-deb-pkg-tools
# SPDX-License-Identifier: MIT
#
# Visit https://aboutcode.org and https://github.com/nexB/univers for support and download.

from __future__ import annotations

import logging
import operator as operator_module
import re
from functools import cmp_to_key
from itertools import zip_longest
from typing import Any, Callable, Dict, List, Match, Optional, Pattern, Tuple, Type, Union # Added necessary types

from attr import asdict, attrib, attrs
# from attr import Factory # Not used directly but good to know for mutable defaults

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


@attrs(eq=False, order=False, frozen=True, hash=False, slots=True, str=False) # str=False means __str__ is user-defined
class Version: # Implicitly object subclass
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

    epoch: int = attrib(default=0)
    # Upstream should be string, from_string ensures this. Default None is for attr internal before from_string.
    upstream: str = attrib(default='') # Default to empty string if not provided, though from_string will set it
    revision: str = attrib(default="0")

    def __str__(self, *args: Any, **kwargs: Any) -> str:
        version_str: str # Renamed
        if self.epoch:
            version_str = f"{self.epoch}:{self.upstream}"
        else:
            version_str = f"{self.upstream}" # self.upstream should be a string here

        # self.revision can be "0" or other string. None case for revision should be handled by from_string.
        if self.revision and self.revision != "0": # Check if revision is non-empty and not "0"
            version_str += f"-{self.revision}"

        return version_str

    def __repr__(self, *args: Any, **kwargs: Any) -> str:
        return f"{self.__class__.__name__}('{str(self)}')" # More conventional repr

    def __hash__(self) -> int:
        return hash(self.tuple())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return self.tuple() == other.tuple()

    def __ne__(self, other: object) -> bool:
        # This can be `return not (self == other)` if using Python 3 style for __ne__
        return not self.__eq__(other)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        # Ensure other is also a Version for eval_constraint if it expects Version objects
        return eval_constraint(self, "<<", other) # type: ignore[arg-type]

    def __le__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, "<=", other) # type: ignore[arg-type]

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, ">>", other) # type: ignore[arg-type]

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, self.__class__):
            return NotImplemented
        return eval_constraint(self, ">=", other) # type: ignore[arg-type]

    @classmethod
    def from_string(cls: Type[Version], version_str: str) -> Version: # Renamed version
        if not version_str or not isinstance(version_str, str): # Check if empty or not string
            raise ValueError(f'Invalid version string: "{version_str}"')

        processed_version_str = version_str.strip() # Renamed
        if not processed_version_str:
            raise ValueError(f'Invalid version string (empty after strip): "{version_str}"')

        # is_valid itself can be a method of the class or a static/module level function.
        # cls.is_valid implies it's a classmethod or staticmethod if called this way.
        if not cls.is_valid(processed_version_str):
            raise ValueError(f'Invalid version string format: "{version_str}"')

        epoch_val: int # Renamed
        # version_part is the remainder after epoch
        version_part: str = processed_version_str
        if ":" in processed_version_str:
            epoch_str, _, version_part = processed_version_str.partition(":")
            try:
                epoch_val = int(epoch_str)
            except ValueError: # Handle non-integer epoch
                 raise ValueError(f'Invalid epoch in version string: "{version_str}"')
        else:
            epoch_val = 0

        # version_part now holds <upstream>[-<revision>] or just <upstream>
        upstream_val: str # Renamed
        revision_val: str # Renamed
        if "-" in version_part: # Check for revision
            # rpartition is good: "a-b-c" -> ("a-b", "-", "c")
            upstream_val, _, revision_val = version_part.rpartition("-")
            # Handle cases like "foo-" (empty revision) or if revision part is invalid.
            # Debian policy might specify constraints on revision format.
            # For now, assume rpartition gives valid parts.
        else:
            upstream_val = version_part
            revision_val = "0" # Default revision if not present

        return cls(epoch=epoch_val, upstream=upstream_val, revision=revision_val)

    @classmethod
    def is_valid(cls: Type[Version], version_str: str) -> bool: # Renamed version
        # is_valid_debian_version is a callable (method of compiled regex)
        match_obj: Optional[Match[str]] = is_valid_debian_version(version_str)
        return bool(match_obj)


    def compare(self, other_version: Union[Version, str]) -> int:
        return compare_versions(self, other_version)

    def to_dict(self) -> Dict[str, Any]: # Return type is Dict[str, Any] from asdict
        return asdict(self)

    def tuple(self) -> Tuple[int, str, str]:
        return self.epoch, self.upstream, self.revision


# This is a method, the result of re.compile(...).match
# Type is Callable[[str], Optional[Match[str]]]
is_valid_debian_version: Callable[[str], Optional[Match[str]]] = re.compile(
    r"^"
    # epoch must start with a digit
    r"(\d+:)?" # Optional epoch
    # upstream must start with a digit
    r"\d" # Upstream version part must start with a digit
    r"("
    # upstream can contain only alphanumerics and the characters . + - ~
    # (full stop, plus, hyphen, tilde)
    # This part allows for complex upstream versions.
    # It seems to allow an optional revision-like part within upstream itself if no -revision follows.
    # Or, more simply, it allows characters including '-' if it's not the delimiter for the main revision.
    r"[A-Za-z0-9\.\+\~\-]*" # Changed from + to * to allow single digit upstream like "1"
                           # And allow trailing punctuations
    # The original regex was:
    # r"[A-Za-z0-9\.\+\~\-]+"  # Original part 1 for complex upstream
    # r"|"
    # r"[A-Za-z0-9\.\+\~]+-[A-Za-z0-9\+\.\~]+" # Original part 2 for upstream with internal hyphen but no main revision
    # This has been simplified to allow hyphens generally in upstream,
    # as the main revision splitting is done by rpartition("-") in from_string.
    # The key is that `upstream` itself must start with a digit.
    r")?" # This group for the rest of upstream is optional if upstream is single digit
    # Optional revision part. If present, must be preceded by a hyphen.
    # The content of revision can be similar to upstream.
    r"(-[A-Za-z0-9\.\+\~\-]+)?"
    r"$"
).match


def eval_constraint(version1: Union[Version, str], operator_str: str, version2: Union[Version, str]) -> bool: # Renamed operator
    """
    Evaluate a versions constraint where two Debian package versions are
    compared with an operator such as < or >. Return True if the constraint is
    satisfied and False otherwise.
    """

    coerced_version1: Version = coerce_version(version1) # Renamed
    coerced_version2: Version = coerce_version(version2) # Renamed

    comparison_result: int = compare_versions(coerced_version1, coerced_version2) # Renamed
    # See https://www.debian.org/doc/debian-policy/ch-relationships.html#syntax-of-relationship-fields
    # Using a Dict to map operator strings to functions from operator_module
    operator_map: Dict[str, Callable[[int, int], bool]] = {
        "<<": operator_module.lt,
        "<=": operator_module.le,
        "=": operator_module.eq,
        ">=": operator_module.ge,
        ">>": operator_module.gt,
        # legacy for compat
        "<": operator_module.lt, # Note: '<' and '>' are not standard in policy for version constraints
        ">": operator_module.gt, # but often used. Policy uses <<, <=, =, >=, >>.
    }

    try:
        op_func = operator_map[operator_str] # Renamed
    except KeyError:
        msg = f"Unsupported Debian version constraint comparison operator: {version1} {operator_str} {version2}"
        raise ValueError(msg) from None # from None to break chain with KeyError
    return op_func(comparison_result, 0)


def compare_versions_key(x: Union[Version, str]) -> Any: # cmp_to_key returns a suitable key object
    """
    Return a key version function suitable for use in sorted().
    """
    # compare_versions is (Version | str, Version | str) -> int
    # cmp_to_key needs a cmp function (Any, Any) -> int
    # This should work as cmp_to_key adapts it.
    return cmp_to_key(compare_versions)(x)


def compare_strings_key(x: str) -> Any: # cmp_to_key returns a suitable key object
    """
    Return a key string function suitable for use in sorted().
    """
    return cmp_to_key(compare_strings)(x)


def compare_strings(string1: str, string2: str) -> int: # Renamed version1, version2
    """
    Compare two version strings (upstream or revision) using Debian semantics
    and return one of the following integer numbers:
        - -1 means string1 sorts before string2
        - 0 means string1 and string2 are equal
        - 1 means string1 sorts after string2
    """
    logger.debug("Comparing Debian version number substrings %r and %r ..", string1, string2)
    # `characters_order` is defined globally
    # Convert strings to lists of characters to allow mutable operations (pop)
    list1: List[str] = list(string1) # Renamed v1
    list2: List[str] = list(string2) # Renamed v2

    while list1 or list2: # Loop as long as either list has characters
        # Part 1: Lexical comparison of non-digit prefixes
        prefix1: List[str] = get_non_digit_prefix(list1) # Renamed p1
        prefix2: List[str] = get_non_digit_prefix(list2) # Renamed p2

        if prefix1 != prefix2:
            logger.debug("Comparing non-digit prefixes %r and %r ..", prefix1, prefix2)
            for char1, char2 in zip_longest(prefix1, prefix2, fillvalue=""): # Renamed c1, c2
                logger.debug(
                    "Performing lexical comparison between characters %r and %r ..", char1, char2
                )
                # `characters_order.get` can return None if char not in map. Needs handling.
                # Assuming all relevant chars are in `characters_order`.
                # The original map has "" mapped to 1, which zip_longest uses as fillvalue.
                order1: Optional[int] = characters_order.get(char1) # Renamed o1
                order2: Optional[int] = characters_order.get(char2) # Renamed o2

                # This comparison assumes all characters will be in `characters_order`
                # Or that None is handled appropriately by comparison (it's not, raises TypeError)
                # The `characters_order` map needs to be comprehensive for all expected chars.
                # Given the map, None should not occur if inputs are valid Debian chars.
                if order1 is None or order2 is None:
                    # This case implies an unexpected character not in `characters_order`
                    # Fallback to simple string comparison for these unknown chars, or error
                    # For now, assume valid inputs means order1/order2 will be int.
                    # A more robust solution would define behavior for unknown chars.
                    # Let's assume this won't happen with valid Debian version strings.
                    # If it could, `ord()` might be a fallback, but Debian has specific rules.
                    raise ValueError(f"Unexpected character in version string part: '{char1}' or '{char2}'")


                if order1 < order2:
                    logger.debug(
                        "Determined that %r sorts before %r (based on lexical comparison).",
                        string1, # Original full string for logging
                        string2,
                    )
                    return -1
                elif order1 > order2:
                    logger.debug(
                        "Determined that %r sorts after %r (based on lexical comparison).",
                        string1,
                        string2,
                    )
                    return 1
        elif prefix1: # Only log if prefix1 (and thus prefix2) was non-empty and they matched
            logger.debug("Skipping matching non-digit prefix %r ..", "".join(prefix1)) # Log joined string


        # Part 2: Numerical comparison of digit prefixes
        num1: int = get_digit_prefix(list1) # Renamed d1
        num2: int = get_digit_prefix(list2) # Renamed d2

        logger.debug("Comparing numeric prefixes %i and %i ..", num1, num2)
        if num1 < num2:
            logger.debug(
                "Determined that %r sorts before %r (based on numeric comparison).",
                string1,
                string2,
            )
            return -1
        elif num1 > num2:
            logger.debug(
                "Determined that %r sorts after %r (based on numeric comparison).",
                string1,
                string2,
            )
            return 1
        # If numeric prefixes are also equal, continue loop with remaining parts of strings.
        # No explicit log here if they match, loop continues or exits if both lists are empty.

    # If loop finishes, all parts were equal
    logger.debug("Determined that version strings are equal.")
    return 0


def compare_versions(version1: Union[Version, str], version2: Union[Version, str]) -> int:
    """
    Compare two Version objects or strings and return one of the following
    integer numbers:

      - -1 means version1 sorts before version2
      - 0 means version1 and version2 are equal
      - 1 means version1 sorts after version2
    """
    coerced_v1: Version = coerce_version(version1) # Renamed
    coerced_v2: Version = coerce_version(version2) # Renamed
    return compare_version_objects(coerced_v1, coerced_v2)


def coerce_version(value: Union[Version, str]) -> Version:
    """
    Return a Version object from value.

    :param value: The value to coerce (a string or :class:`Version` object).
    :returns: A :class:`Version` object.
    """
    if not isinstance(value, Version):
        # Assuming value is str if not Version, after initial type hint Union[Version, str]
        return Version.from_string(str(value)) # Ensure it's a string for from_string
    return value


def compare_version_objects(obj1: Version, obj2: Version) -> int: # Renamed version1, version2
    """
    Compare two Version objects and return one of the following
    integer numbers:

      - -1 means obj1 sorts before obj2
      - 0 means obj1 and obj2 are equal
      - 1 means obj1 sorts after obj2
    """
    # Compare epochs first
    if obj1.epoch < obj2.epoch:
        return -1
    if obj1.epoch > obj2.epoch:
        return 1

    # If epochs are equal, compare upstream versions
    # obj1.upstream and obj2.upstream should be strings
    upstream_comparison_result: int = compare_strings(obj1.upstream, obj2.upstream) # Renamed
    if upstream_comparison_result != 0:
        return upstream_comparison_result

    # If upstreams are also equal, compare Debian revisions
    # obj1.revision and obj2.revision should be strings.
    # Policy: "0" revision is same as empty or no revision if other parts equal.
    # compare_strings should handle "0" vs actual revision string correctly if needed.
    # The original logic `if version1.revision or version2.revision:` might be trying to
    # optimize for cases where both are "0" or default, but compare_strings handles "0" vs "0".
    # Let's simplify to always compare revisions if upstreams are equal.
    # If one revision is "0" (default) and other is genuinely "0", they are equal.
    # If one is "0" and other is non-"0", compare_strings handles it.
    return compare_strings(obj1.revision, obj2.revision)


def get_digit_prefix(characters: List[str]) -> int: # characters is a list of char strings
    """
    Return the digit prefix from a list of characters.
    Modifies the list by popping characters.
    """
    value_str: str = "" # Renamed
    while characters and characters[0].isdigit():
        value_str += characters.pop(0)
    return int(value_str) if value_str else 0 # Return 0 if no digits found


def get_non_digit_prefix(characters: List[str]) -> List[str]: # characters is a list of char strings
    """
    Return the non-digit prefix from a list of characters.
    Modifies the list by popping characters.
    """
    prefix_list: List[str] = [] # Renamed
    while characters and not characters[0].isdigit():
        prefix_list.append(characters.pop(0))
    return prefix_list


# a mapping of characters to integers representing the Debian sort order.
characters_order: Dict[str, int] = {
    # The tilde sorts before everything.
    "~": 0,
    # The empty string sort before everything except a tilde.
    # This is used by zip_longest fillvalue.
    "": 1,
    # Letters sort before everything but a tilde or empty string,
    # in their regular lexical sort order.
    # Python's string comparison `ord(c)` would work for ASCII letters too,
    # but this explicit map defines a specific order if needed beyond ASCII.
    # Assuming standard ASCII for letters if not in map.
    # The map should cover all expected characters in version strings.
    # For simplicity, only mapped ones are shown, but a full map or logic for others is needed.
    # Based on Debian policy: "all the letters sort earlier than all the non-letters"
    # This map needs to reflect that. The current one does: letters (A-Z, a-z) are 2-53.
    # Non-letters (+, -, .) are 54-56. Digits are handled separately.
    "A": 2, "B": 3, "C": 4, "D": 5, "E": 6, "F": 7, "G": 8, "H": 9, "I": 10,
    "J": 11, "K": 12, "L": 13, "M": 14, "N": 15, "O": 16, "P": 17, "Q": 18,
    "R": 19, "S": 20, "T": 21, "U": 22, "V": 23, "W": 24, "X": 25, "Y": 26, "Z": 27,
    "a": 28, "b": 29, "c": 30, "d": 31, "e": 32, "f": 33, "g": 34, "h": 35, "i": 36,
    "j": 37, "k": 38, "l": 39, "m": 40, "n": 41, "o": 42, "p": 43, "q": 44, "r": 45,
    "s": 46, "t": 47, "u": 48, "v": 49, "w": 50, "x": 51, "y": 52, "z": 53,
    # Punctuation characters follow in their regular lexical sort order AFTER letters.
    # But Debian policy says: "all the letters sort earlier than all the non-letters".
    # This means non-letters (excluding tilde) should have higher values than letters.
    # The provided map seems to align with this.
    "+": 54,
    "-": 55,
    ".": 56,
    # Other non-alphanumeric characters would need to be mapped if they can occur
    # and have a defined order. Otherwise, `characters_order.get()` might return None.
}
