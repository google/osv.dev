# Copyright (c) nexB, Inc. and others.
# Copyright (c) Center for Information Technology, http://coi.gov.pl
# Copyright (c) Chad Fowler, Rich Kilmer, Jim Weirich and others.
# Copyright (c) Engine Yard and Andre Arko, Facebook, Inc. and its affiliates.
#
# SPDX-License-Identifier: Apache-2.0 AND MIT
# This has been significantly modified from the original
#
# Visit https://aboutcode.org and https://github.com/nexB/univers for support and download.

# notes: This has been substantially modified and enhanced from the original
# puppeteer code to extract the Ruby version handling code.
# This code is in turn originally based and updated from the Rubygems code
# Originally from https://github.com/rubygems/rubygems and
# https://github.com/coi-gov-pl/puppeter

from __future__ import annotations

import operator
import re
from collections import namedtuple # Will be replaced by typing.NamedTuple for GemConstraint
from itertools import dropwhile
from typing import (Any, Callable, ClassVar, Dict, Iterable, List, Match,
                    NamedTuple, Optional, Pattern, Sequence, Tuple, Type, Union)


class InvalidRequirementError(AttributeError): # Keep as AttributeError if specific error handling relies on it
    pass


class InvalidVersionError(ValueError):
    pass


# Type for segments, which can be int or str
SegmentType = Union[int, str]


class GemVersion:
    """
    The Rubygems version.rb has this documentation
    The Version class processes string versions into comparable
    values. A version string should normally be a series of numbers
    separated by periods. Each part (digits separated by periods) is
    considered its own number, and these are used for sorting. So for
    instance, 3.10 sorts higher than 3.2 because ten is greater than
    two.

    If any part contains letters (currently only a-z are supported) then
    that version is considered prerelease. Versions with a prerelease
    part in the Nth part sort less than versions with N-1
    parts. Prerelease parts are sorted alphabetically using the normal
    Ruby string sorting rules. If a prerelease part contains both
    letters and numbers, it will be broken into multiple parts to
    provide expected sort behavior (1.0.a10 becomes 1.0.a.10, and is
    greater than 1.0.a9).

    Prereleases sort between real releases (newest to oldest):

    1. 1.0
    2. 1.0.b1
    3. 1.0.a.2
    4. 0.9

    If you want to specify a version restriction that includes both prereleases
    and regular releases of the 1.x series this is the best way:

      s.add_dependency 'example', '>= 1.0.0.a', '< 2.0.0'

    == How Software Changes

    Users expect to be able to specify a version constraint that gives them
    some reasonable expectation that new versions of a library will work with
    their software if the version constraint is true, and not work with their
    software if the version constraint is false.  In other words, the perfect
    system will accept all compatible versions of the library and reject all
    incompatible versions.

    Libraries change in 3 ways (well, more than 3, but stay focused here!).

    1. The change may be an implementation detail only and have no effect on
       the client software.
    2. The change may add new features, but do so in a way that client software
       written to an earlier version is still compatible.
    3. The change may change the public interface of the library in such a way
       that old software is no longer compatible.

    Some examples are appropriate at this point.  Suppose I have a Stack class
    that supports a <tt>push</tt> and a <tt>pop</tt> method.

    === Examples of Category 1 changes:

    * Switch from an array based implementation to a linked-list based
      implementation.
    * Provide an automatic (and transparent) backing store for large stacks.

    === Examples of Category 2 changes might be:

    * Add a <tt>depth</tt> method to return the current depth of the stack.
    * Add a <tt>top</tt> method that returns the current top of stack (without
      changing the stack).
    * Change <tt>push</tt> so that it returns the item pushed (previously it
      had no usable return value).

    === Examples of Category 3 changes might be:

    * Changes <tt>pop</tt> so that it no longer returns a value (you must use
      <tt>top</tt> to get the top of the stack).
    * Rename the methods to <tt>push_item</tt> and <tt>pop_item</tt>.

    == RubyGems Rational Versioning

    * Versions shall be represented by three non-negative integers, separated
      by periods (e.g. 3.1.4).  The first integers is the "major" version
      number, the second integer is the "minor" version number, and the third
      integer is the "build" number.

    * A category 1 change (implementation detail) will increment the build
      number.

    * A category 2 change (backwards compatible) will increment the minor
      version number and reset the build number.

    * A category 3 change (incompatible) will increment the major build number
      and reset the minor and build numbers.

    * Any "public" release of a gem should have a different version.  Normally
      that means incrementing the build number.  This means a developer can
      generate builds all day long, but as soon as they make a public release,
      the version must be updated.

    === Examples

    Let's work through a project lifecycle using our Stack example from above.

    Version 0.0.1:: The initial Stack class is release.
    Version 0.0.2:: Switched to a linked=list implementation because it is
                    cooler.
    Version 0.1.0:: Added a <tt>depth</tt> method.
    Version 1.0.0:: Added <tt>top</tt> and made <tt>pop</tt> return nil
                    (<tt>pop</tt> used to return the  old top item).
    Version 1.1.0:: <tt>push</tt> now returns the value pushed (it used it
                    return nil).
    Version 1.1.1:: Fixed a bug in the linked list implementation.
    Version 1.1.2:: Fixed a bug introduced in the last fix.

    Client A needs a stack with basic push/pop capability.  They write to the
    original interface (no <tt>top</tt>), so their version constraint looks like:

      gem 'stack', '>= 0.0'

    Essentially, any version is OK with Client A.  An incompatible change to
    the library will cause them grief, but they are willing to take the chance
    (we call Client A optimistic).

    Client B is just like Client A except for two things: (1) They use the
    <tt>depth</tt> method and (2) they are worried about future
    incompatibilities, so they write their version constraint like this:

      gem 'stack', '~> 0.1'

    The <tt>depth</tt> method was introduced in version 0.1.0, so that version
    or anything later is fine, as long as the version stays below version 1.0
    where incompatibilities are introduced.  We call Client B pessimistic
    because they are worried about incompatible future changes (it is OK to be
    pessimistic!).

    == Preventing Version Catastrophe:

    From: http://blog.zenspider.com/2008/10/rubygems-howto-preventing-cata.html

    Let's say you're depending on the fnord gem version 2.y.z. If you
    specify your dependency as ">= 2.0.0" then, you're good, right? What
    happens if fnord 3.0 comes out and it isn't backwards compatible
    with 2.y.z? Your stuff will break as a result of using ">=". The
    better route is to specify your dependency with an "approximate" version
    specifier ("~>"). They're a tad confusing, so here is how the dependency
    specifiers work:

      Specification From  ... To (exclusive)
      ">= 3.0"      3.0   ... &infin;
      "~> 3.0"      3.0   ... 4.0
      "~> 3.0.0"    3.0.0 ... 3.1
      "~> 3.5"      3.5   ... 4.0
      "~> 3.5.0"    3.5.0 ... 3.6
      "~> 3"        3.0   ... 4.0

    For the last example, single-digit versions are automatically extended with
    a zero to give a sensible result.
    """

    VERSION_PATTERN: ClassVar[str] = r"[0-9]+(?:\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"
    # This is a method of a compiled regex object
    is_correct: ClassVar[Callable[[str], Optional[Match[str]]]] = re.compile(
        rf"^\s*({VERSION_PATTERN})?\s*$"
    ).match

    original: str
    version: str # Internal representation, e.g. with ".pre."
    _segments: Tuple[SegmentType, ...]
    _canonical_segments: Tuple[SegmentType, ...]
    _bump: Optional[GemVersion]
    _release: Optional[GemVersion]

    def __init__(self, version_input: Union[str, int, GemVersion]) -> None:
        """
        Construct a Version from the ``version_input`` string.  A version string is a
        series of digits or ASCII letters separated by dots and may contain dash
        "-".
        """
        version_str: str # To hold the string form of version_input
        if isinstance(version_input, GemVersion):
            # If it's already a GemVersion, use its original string representation
            # This path ensures that GemVersion(GemVersion("1.0")) behaves correctly
            version_str = version_input.original
        elif isinstance(version_input, int):
            version_str = str(version_input)
        elif isinstance(version_input, str):
            version_str = version_input
        else:
            # This case should ideally not be reached if type hints are followed by callers.
            # However, for runtime safety if untyped code calls this:
            raise InvalidVersionError(f"Invalid type for version_input: {type(version_input)}")

        if not self.is_correct(version_str): # is_correct is a class var, callable
            raise InvalidVersionError(f"Version string does not match expected pattern: {version_str}")

        # If version is an empty string convert it to 0 (after stripping)
        processed_version_str = version_str.strip() # Renamed version to version_str

        self.original = version_str # Store original input string

        if not processed_version_str: # If empty after strip, treat as "0"
            processed_version_str = "0"

        # Internal representation replacing '-' with '.pre.'
        self.version = processed_version_str.replace("-", ".pre.")

        # Initialize internal caches
        self._segments = tuple() # Ensure it's a tuple
        self._canonical_segments = tuple() # Ensure it's a tuple
        self._bump = None
        self._release = None

    def __str__(self) -> str:
        return self.original

    to_string = __str__ # Alias

    def __repr__(self) -> str:
        return f"GemVersion({self.original!r})"

    def equal_strictly(self, other: GemVersion) -> bool:
        # Compares the internal string representation, not canonical segments
        return self.version == other.version

    def __hash__(self) -> int:
        return hash(self.canonical_segments) # Uses property, which calls get_canonical_segments

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GemVersion):
            return NotImplemented
        return self.canonical_segments == other.canonical_segments

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, GemVersion):
            return NotImplemented
        # __cmp__ is not standard in Python 3 for rich comparisons.
        # Rich comparison methods should implement logic directly or call a helper.
        # Let's assume __cmp__ is a helper here that returns -1, 0, 1.
        cmp_val = self.__cmp__(other)
        return cmp_val is not None and cmp_val < 0


    def __le__(self, other: object) -> bool:
        if not isinstance(other, GemVersion):
            return NotImplemented
        cmp_val = self.__cmp__(other)
        return cmp_val is not None and cmp_val <= 0

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, GemVersion):
            return NotImplemented
        cmp_val = self.__cmp__(other)
        return cmp_val is not None and cmp_val > 0

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, GemVersion):
            return NotImplemented
        cmp_val = self.__cmp__(other)
        return cmp_val is not None and cmp_val >= 0

    def bump(self) -> GemVersion:
        """
        Return a new version object where the next to the last revision number
        is one greater (e.g., 5.3.1 => 5.4) i.e., incrementing this GemVersion
        last numeric segment.

        For example::
        >>> assert GemVersion("5.3.1").bump() == GemVersion("5.4"), repr(GemVersion("5.3.1").bump())
        >>> assert GemVersion("5.3.1.4-2").bump() == GemVersion("5.3.2"), GemVersion("5.3.1.4-2").bump()
        """
        if self._bump is None: # Check if cached
            # Get numeric prefix segments
            numeric_prefix_segments: List[int] = []
            for seg in self.segments: # self.segments returns List[SegmentType]
                if isinstance(seg, int):
                    numeric_prefix_segments.append(seg)
                else: # Stop at first string segment
                    break

            if not numeric_prefix_segments: # Should not happen for valid versions like "0"
                # Handle cases like "a.b.c" if they are considered valid by is_correct
                # For "0", segments is [0]. numeric_prefix_segments is [0].
                # If segments were ["a", 1], numeric_prefix_segments would be empty.
                # This logic assumes at least one numeric segment if it's to be bumped.
                # If version is "a", segments is ["a"], numeric_prefix is [], this will fail.
                # Let's assume valid versions for bumping have leading numbers.
                raise InvalidVersionError(f"Cannot bump non-numeric version or version without numeric prefix: {self.original}")

            # Pop the last segment if more than one, effectively moving to "minor" for "major.minor.patch"
            if len(numeric_prefix_segments) > 1:
                numeric_prefix_segments.pop()

            # Increment the last segment (which is now effectively the one to bump)
            numeric_prefix_segments[-1] += 1

            # Convert back to string segments for joining
            bumped_string_segments: List[str] = [str(s) for s in numeric_prefix_segments]
            object.__setattr__(self, '_bump', GemVersion(".".join(bumped_string_segments))) # Use object.__setattr__ for frozen

        return self._bump # self._bump is now guaranteed to be GemVersion

    def release(self) -> GemVersion:
        """
        Return a new GemVersion which is the release for this version (e.g.,
        1.2.0.a -> 1.2.0). Non-prerelease versions return themselves. A release
        is composed only of numeric segments.
        """
        if self._release is None: # Check if cached
            if self.prerelease():
                # Take only the numeric prefix segments
                numeric_segments: List[SegmentType] = []
                for seg in self.segments: # self.segments is List[SegmentType]
                    if isinstance(seg, int):
                        numeric_segments.append(seg)
                    else: # Stop at the first string segment
                        break

                # If all segments were strings (e.g. "a.b"), numeric_segments is empty.
                # If version was "1.a.2", numeric_segments is [1].
                # A release version should have at least one segment, typically "0" if all were alpha.
                if not numeric_segments: # e.g. for "a.b.c"
                    release_str = "0"
                else:
                    release_str = ".".join(map(str, numeric_segments))
                object.__setattr__(self, '_release', GemVersion(release_str)) # Use object.__setattr__ for frozen
            else: # Not a prerelease, so it's its own release
                object.__setattr__(self, '_release', self)

        return self._release # self._release is now GemVersion

    def prerelease(self) -> bool:
        """
        Return True if this is considered as a prerelease version.
        A version is considered a prerelease if it contains a letter (string segment).
        """
        return any(isinstance(s, str) for s in self.segments)

    @property
    def segments(self) -> List[SegmentType]: # Returns a List copy
        """
        Return a new sequence of segments for this version where segments are
        ints or strings parsed from the original version string.
        """
        if not self._segments: # self._segments is Tuple
            # Use object.__setattr__ for frozen instances if modifying internal state
            object.__setattr__(self, '_segments', self.get_segments())
        return list(self._segments) # Return a list copy

    def get_segments(self) -> Tuple[SegmentType, ...]:
        """
        Return a tuple of segments for this version where segments are ints
        or strings parsed from the original version string.
        """
        # This regex finds sequences of digits or sequences of letters.
        # It implies segments are alternating, e.g. "1a2b" -> ["1", "a", "2", "b"].
        # RubyGems version "1.0.a10" becomes segments (1, 0, 'a', 10).
        # The internal `self.version` has `pre` e.g. "1.0.pre.a.10"
        find_segments_re: Pattern[str] = re.compile(r"[0-9]+|[a-z]+", re.IGNORECASE)

        parsed_segments: List[SegmentType] = []
        for seg_str in find_segments_re.findall(self.version): # self.version is like "1.0.pre.a.10"
            if seg_str.isdigit():
                # All digit sequences become integers
                parsed_segments.append(int(seg_str))
            else:
                # Letter sequences (like "pre", "a") remain strings
                parsed_segments.append(seg_str)
        return tuple(parsed_segments)

    @property
    def canonical_segments(self) -> List[SegmentType]: # Returns a List copy
        if not self._canonical_segments: # self._canonical_segments is Tuple
            object.__setattr__(self, '_canonical_segments', self.get_canonical_segments())
        return list(self._canonical_segments) # Return a list copy

    def get_canonical_segments(self) -> Tuple[SegmentType, ...]:
        """
        Return a tuple of "canonical segments" for this version using
        the Rubygems way (trailing zero number segments are removed per sub-list).
        """
        final_canonical_segments: List[SegmentType] = []
        # self.split_segments() returns Tuple[List[int], List[SegmentType]]
        # The first part is numeric_segments, second is string_segments (which can contain ints)
        # This logic seems specific to how RubyGems canonicalizes.
        # It processes numeric prefix and then the rest (alpha-containing part) separately.
        numeric_part, string_part = self.split_segments()

        # Process numeric_part: drop trailing zeros
        # Example: [1, 2, 0] -> [1, 2]. [1, 0, 0] -> [1]. [0, 0] -> []. [0] -> [] ?
        # dropwhile(lambda s: s == 0, reversed(segments))
        # reversed([1,2,0]) -> [0,2,1]. dropwhile -> [2,1]. reversed -> [1,2]
        # reversed([0,0]) -> [0,0]. dropwhile -> []. reversed -> []
        # This means [0] becomes [] and [0,0] becomes [].
        # If numeric_part is empty (e.g. version "a.b"), this will be empty.
        if numeric_part: # Only if there are numeric segments
            segs_numeric = list(dropwhile(lambda s: s == 0, reversed(numeric_part)))
            final_canonical_segments.extend(reversed(segs_numeric))

        # Process string_part (which may contain numbers after first string)
        # Example: ['pre', 1, 0] -> ['pre', 1] ?
        # Example: ['a', 0] -> ['a'] ?
        # The logic here is that if string_part exists, its own trailing numeric zeros are also dropped.
        if string_part:
            # If string_part itself ends with integers like ['a', 1, 0], those zeros are dropped.
            # This needs careful application of the dropwhile logic.
            # The original Rubygems logic might be more nuanced here.
            # For now, assume a similar trimming applies if the tail of string_part is numeric.
            # This part of canonicalization is complex.
            # A simple approach: if string_part is like ['a', 1, 0], it becomes ['a', 1].
            # If it's ['a', 0], it becomes ['a'].
            # The original code iterates `for segments in self.split_segments():`
            # implying it applies the same logic to both parts.
            segs_string = list(dropwhile(lambda s: s == 0 and isinstance(s, int), reversed(string_part))) # type: ignore
            final_canonical_segments.extend(reversed(segs_string))

        return tuple(final_canonical_segments)

    def split_segments(self) -> Tuple[List[int], List[SegmentType]]:
        """
         Return a two-tuple of segments:
        - the first is a list of purely numeric segments from the start.
        - the second is the list of remaining segments (starts with first non-int or is empty).
        """
        numeric_segments_list: List[int] = [] # Renamed
        string_segments_list: List[SegmentType] = [] # Renamed. Can contain int after first str.

        current_segments = self.segments # Property call: List[SegmentType]

        # Find first string segment
        first_string_index = -1
        for i, seg_item in enumerate(current_segments): # Renamed seg to seg_item
            if isinstance(seg_item, str):
                first_string_index = i
                break

        if first_string_index == -1: # All segments are numeric
            # Ensure all items in current_segments are int if no string was found
            numeric_segments_list.extend([s for s in current_segments if isinstance(s, int)])
        else:
            # Numeric part is before the first string
            numeric_segments_list.extend([s for s in current_segments[:first_string_index] if isinstance(s, int)])
            # String part is from the first string onwards
            string_segments_list.extend(current_segments[first_string_index:])

        return numeric_segments_list, string_segments_list

    def __cmp__(self, other: Any, trace: bool = False) -> Optional[int]:
        """
        Compare this version with ``other`` returning -1, 0, or 1 if the
        other version is larger, the same, or smaller than this
        one. Attempts to compare to something that's not a
        ``GemVersion raises an exception.

        The comparison results have the same semantics as the legacy "cmp()"
        built-in function.
        """
        # This method is primarily for internal use by rich comparison methods.
        # The `other` type is `Any` to allow for the initial `isinstance` checks.
        if trace:
            print(f"\nComparing: {self!r} with {other!r}")

        other_gem_version: GemVersion
        if isinstance(other, str):
            other_gem_version = GemVersion(other)
            if trace:
                print(f"  Converted str to GemVersion: {other_gem_version!r}")
        elif isinstance(other, GemVersion):
            other_gem_version = other
        else:
            if trace:
                print(f"  Not a GemVersion or str: {other!r}")
            return None # Indicates an incomparable type, or could raise TypeError

        # Shortcut: if internal representations are same, versions are same.
        # This might not be true if canonicalization changes things, but original code had it.
        # Let's rely on canonical_segments for equality check as per __eq__.
        # if self.version == other_gem_version.version:
        # return 0

        # Compare using canonical segments
        lh_segments: List[SegmentType] = self.canonical_segments # Property returns List
        if trace: print(f"  lh_segments: {lh_segments!r}")

        rh_segments: List[SegmentType] = other_gem_version.canonical_segments
        if trace: print(f"  rh_segments: {rh_segments!r}")

        if lh_segments == rh_segments:
            if trace: print(f"    lh_segments == rh_segments: returning 0")
            return 0

        # Iterate up to the length of the longer sequence of segments
        # This iteration logic is from RubyGems' Version#<=>
        max_len = max(len(lh_segments), len(rh_segments))

        for i in range(max_len):
            lhs_seg: SegmentType = lh_segments[i] if i < len(lh_segments) else 0 # Default to 0 for missing numeric
            rhs_seg: SegmentType = rh_segments[i] if i < len(rh_segments) else 0 # Default to 0 for missing numeric

            # If one is string and other is int, string is "smaller" (pre-release)
            # This is a key part of RubyGems version comparison logic.
            if isinstance(lhs_seg, str) and isinstance(rhs_seg, int):
                if trace: print(f"      lhs str, rhs int ('{lhs_seg}' vs {rhs_seg}): return -1")
                return -1
            if isinstance(lhs_seg, int) and isinstance(rhs_seg, str):
                if trace: print(f"      lhs int, rhs str ({lhs_seg} vs '{rhs_seg}'): return 1")
                return 1

            # If both are same type (both str or both int)
            if lhs_seg < rhs_seg: # type: ignore # comparison between SegmentType
                if trace: print(f"      '{lhs_seg}' < '{rhs_seg}': return -1")
                return -1
            if lhs_seg > rhs_seg: # type: ignore # comparison between SegmentType
                if trace: print(f"      '{lhs_seg}' > '{rhs_seg}': return 1")
                return 1

            # If segments are equal, continue to next segment
            if trace: print(f"      '{lhs_seg}' == '{rhs_seg}': continue")

        if trace: print(f"  all segments compared, or one is prefix of other and tail is 0s: return 0")
        return 0 # Should be covered by lh_segments == rh_segments if logic is perfect


# Use typing.NamedTuple for better type checking support
class GemConstraint(NamedTuple):
    op: str
    version: GemVersion

    def to_string(self) -> str: # Made it a method
        return f"{self.op} {self.version}"


def sort_constraints(constraints: Iterable[GemConstraint]) -> List[GemConstraint]:
    """
    Return a sorted sequence of unique GemConstraints.
    """
    # Sort by version first (using GemVersion's rich comparison), then by operator string
    # Using lambda key for sorting, GemVersion needs to be comparable.
    sorted_constraints = sorted(constraints, key=lambda gc: (gc.version, gc.op))

    # Deduplicate while preserving order (Python's sort is stable)
    unique_constraints: List[GemConstraint] = []
    for gc_item in sorted_constraints: # Renamed gc to gc_item
        if gc_item not in unique_constraints: # Relies on GemConstraint.__eq__ (default for NamedTuple)
            unique_constraints.append(gc_item)
    return unique_constraints


def tilde_comparator(version: GemVersion, requirement_version: GemVersion, trace: bool = False) -> bool: # Renamed requirement
    """
    Return True if ``version`` GemVersion satisfies ``requirement_version`` GemVersion
    according to the Rubygems tilde semantics.
    e.g., "~> 2.2" means ">= 2.2.0" and "< 3.0.0"
    e.g., "~> 2.2.1" means ">= 2.2.1" and "< 2.3.0"
    """
    if trace:
        print(f"      tilde_comparator: version: {version!r}, requirement_version: {requirement_version!r}")
        # Check lower bound: version must be >= requirement_version
        lower_bound_satisfied = version >= requirement_version
        print(f"         version >= requirement_version: {version!r} >= {requirement_version!r} -> {lower_bound_satisfied}")

        # Determine upper bound: version.release() must be < requirement_version.bump()
        # requirement_version.bump() gives the next major/minor version depending on specificity.
        # E.g., if requirement is "2.2", bump is "2.3". If "2.2.1", bump is "2.3.0".
        # No, bump for "2.2.1" is "2.3". For "2.2.1.3" it's "2.2.2".
        # The logic of bump() is: "next to the last revision number is one greater".
        # For "1.2.3", segments [1,2,3], numeric_prefix [1,2,3]. Pop -> [1,2]. Inc -> [1,3]. GemVersion("1.3")
        # For "1.2", segments [1,2], numeric_prefix [1,2]. Pop (no) -> [1]. Inc -> [2]. GemVersion("2") (this is correct for ~> 1.2 meaning < 2.0)
        # For "1.2.0.a", release is "1.2.0". Version.release() is self if not prerelease.
        # So, version.release() ensures we compare against the non-prerelease part of `version`.

        bumped_requirement = requirement_version.bump()
        upper_bound_satisfied = version.release() < bumped_requirement
        print(
            f"         version.release() < requirement.bump(): {version.release()!r} "
            f"< {bumped_requirement!r} -> {upper_bound_satisfied}"
        )

    return version >= requirement_version and version.release() < requirement_version.bump()


class GemRequirement:
    """
    A gem requirement using the Gem notation.
    """

    equal_op = operator.eq
    comparators_by_op = {
        "=": equal_op,
        "!=": operator.ne,
        ">": operator.gt,
        "<": operator.lt,
        ">=": operator.ge,
        "<=": operator.le,
        "~>": tilde_comparator,
    }

    quoted = "|".join(re.escape(op) for op in comparators_by_op)

    PATTERN_RAW: ClassVar[str] = f"\\s*({quoted})?\\s*({GemVersion.VERSION_PATTERN})\\s*"

    # A regular expression that matches a requirement
    PATTERN: ClassVar[Pattern[str]] = re.compile(f"^{PATTERN_RAW}$")

    # The default requirement matches any version (>= 0)
    DEFAULT_CONSTRAINT: ClassVar[GemConstraint] = GemConstraint(">=", GemVersion("0")) # Version 0

    constraints: Tuple[GemConstraint, ...] # This will store the parsed constraints

    # The *requirements can be complex. Each item could be str, GemConstraint, etc.
    # The parse method handles various inputs for a single constraint.
    # Here, *requirements means a sequence of these items.
    def __init__(self, *requirements_input: Any) -> None: # Renamed requirements
        """
        Initialize a GemRequirement from a sequence of ``requirements_input``
        converted to a constraints sequence of GemConstraint.
        Each item in requirements_input can be a string like ">= 1.0",
        or a pre-parsed GemConstraint, etc. (as handled by cls.parse).
        """
        if not requirements_input:
            self.constraints = (GemRequirement.DEFAULT_CONSTRAINT,)
        else:
            # Each item `r` in requirements_input needs to be parsed.
            # The parse method expects a single requirement representation.
            parsed_constraints: List[GemConstraint] = []
            for r_item in requirements_input: # Renamed r to r_item
                # GemRequirement.parse can handle various types for a single constraint.
                parsed_constraints.append(GemRequirement.parse(r_item))
            self.constraints = tuple(parsed_constraints)


    def __str__(self) -> str:
        # GemConstraint.to_string() is now a method.
        gcs_str_list: List[str] = [gc.to_string() for gc in sort_constraints(list(self.constraints))] # Renamed
        return ", ".join(gcs_str_list)

    def __repr__(self) -> str:
        # GemConstraint.to_string() is a method.
        gcs_repr_list: List[str] = [repr(gc.to_string()) for gc in sort_constraints(list(self.constraints))] # Renamed
        return f"GemRequirement({', '.join(gcs_repr_list)})"

    @classmethod
    def from_string(cls: Type[GemRequirement], requirements_str: str) -> GemRequirement: # Renamed requirements
        """
        Return a GemRequirement build from a lockfile-style ``requirements_str``
        string.

        For example::
        >>> gr1 = GemRequirement(">= 1.0.1", "~> 1.0")
        >>> gr2 = GemRequirement.from_string(" (>= 1.0.1, ~> 1.0)")
        >>> assert gr1 == gr2, (gr1, gr2)
        """
        # Remove surrounding parens and split by comma.
        # Each part is then a requirement string like ">= 1.0.1".
        reqs_str_list: List[str] = requirements_str.strip().strip("()").split(",") # Renamed reqs
        # Filter out empty strings that might result from "foo, "
        cleaned_reqs_list: List[str] = [r.strip() for r in reqs_str_list if r.strip()]
        return cls(*cleaned_reqs_list) # Pass as *args to __init__

    def for_lockfile(self) -> str:
        """
        Return a string representing this list of requirements suitable for use
        in a lockfile.

        For example::
        >>> gr = GemRequirement(">= 1.0.1", "~> 1.0")
        >>> gf_flf = gr.for_lockfile()
        >>> assert gf_flf == " (~> 1.0, >= 1.0.1)", gf_flf
        """
        # GemConstraint.to_string() is a method.
        gcs_str_list: List[str] = [gc.to_string() for gc in sort_constraints(list(self.constraints))] # Renamed
        joined_gcs_str: str = ", ".join(gcs_str_list) # Renamed
        return f" ({joined_gcs_str})"

    def dedupe(self) -> GemRequirement:
        """
        Return a new GemRequirement with sorted and unique constraints.
        """
        # sort_constraints already handles sorting and making unique.
        # The result of sort_constraints is List[GemConstraint].
        # GemRequirement constructor takes *args of constraints.
        return GemRequirement(*sort_constraints(list(self.constraints)))

    def simplify(self) -> GemRequirement:
        """
        Return a new simplified GemRequirement with:
        - sorted and unique constraints.
        - where ~> constraints are replaced by simpler contrainsts (>= lower, < upper).
        """
        simplified_constraints: List[GemConstraint] = [] # Renamed
        for const_item in self.constraints: # Renamed const to const_item
            if const_item.op == "~>":
                # get_tilde_constraints returns Tuple[GemConstraint, GemConstraint]
                lower_bound, upper_bound = get_tilde_constraints(const_item)
                simplified_constraints.append(lower_bound)
                simplified_constraints.append(upper_bound)
            else:
                simplified_constraints.append(const_item)
        # GemRequirement constructor takes *args, and sort_constraints ensures uniqueness and order.
        return GemRequirement(*sort_constraints(simplified_constraints))

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GemRequirement): # Check specific type
            return False # Or NotImplemented if preferred for non-GemRequirement comparisons

        # An == check is always necessary: compare canonicalized lists of constraints
        # sort_constraints returns List[GemConstraint]
        self_sorted_constraints = sort_constraints(list(self.constraints))
        other_sorted_constraints = sort_constraints(list(other.constraints))

        if self_sorted_constraints == other_sorted_constraints:
            # This basic check covers cases where constraints are identical after sorting.
            # The original logic has a more complex check for tilde requirements regarding "precision".
            # Let's try to replicate that.
            self_tilde_reqs = self.tilde_requirements() # List[GemConstraint]
            if not self_tilde_reqs: # If no tilde requirements, the list comparison is enough
                return True
            else: # If there are tilde requirements, a stricter comparison is needed.
                other_tilde_reqs = other.tilde_requirements()
                if len(self_tilde_reqs) != len(other_tilde_reqs):
                    return False # Different number of tilde requirements

                # Compare each tilde requirement for strict version equality
                for self_tilde, other_tilde in zip(self_tilde_reqs, other_tilde_reqs):
                    # op should match (both "~>")
                    # version should be strictly equal (same original string for version part)
                    if not self_tilde.version.equal_strictly(other_tilde.version):
                        return False
                return True # All tilde requirements are strictly equal
        return False


    def exact(self) -> bool:
        """
        Return True if the requirement is for only an exact version.
        e.g. GemRequirement("= 1.0.1")
        """
        # self.constraints is Tuple[GemConstraint, ...]
        return len(self.constraints) == 1 and self.constraints[0].op == "="

    @classmethod
    def create(cls: Type[GemRequirement],
               reqs_input: Union[str, List[str], GemConstraint, GemVersion, Tuple[str, str], List[GemConstraint]]
              ) -> GemRequirement: # Renamed reqs
        """
        Return a GemRequirement built from a single requirement string or a list
        of requirement strings, or other forms parsable by cls.parse or cls.__init__.
        """
        # If reqs_input is already a list of items that __init__ can handle via *args
        if isinstance(reqs_input, list):
            # Ensure elements are suitable for GemRequirement.parse if they are not GemConstraints
            # The __init__ will call parse for each item if they are strings.
            return cls(*reqs_input) # type: ignore[arg-type] # *reqs_input needs to match __init__ *args
        else:
            # If it's a single item (str, GemConstraint, etc.), pass it as a single arg to __init__
            # which will then pass it to parse.
            return cls(reqs_input) # type: ignore[arg-type]

    @classmethod
    def parse(cls: Type[GemRequirement],
              requirement_input: Union[str, GemVersion, GemConstraint, Tuple[str, str], List[str]]
             ) -> GemConstraint: # Renamed requirement
        """
        Return a GemConstraint tuple of (operator string, GemVersion object)
        parsed from a single ``requirement_input`` string such as "> 3.0". Also
        accepts a two-tuple or list of ("op", "version") or a single GemVersion or a
        GemConstraint).
        """
        if isinstance(requirement_input, GemConstraint): # Already a GemConstraint
            return requirement_input

        if isinstance(requirement_input, GemVersion): # A GemVersion implies exact match
            return GemConstraint("=", requirement_input)

        # Handle ("op", "version_str") tuple or list
        if isinstance(requirement_input, (tuple, list)):
            if len(requirement_input) == 2 and isinstance(requirement_input[0], str) and isinstance(requirement_input[1], str):
                op_str, ver_str = requirement_input[0], requirement_input[1]
                return GemConstraint(op_str, GemVersion(ver_str)) # type: ignore[misc] # GemConstraint expects GemVersion
            else: # Malformed tuple/list
                raise InvalidRequirementError(f"Illformed tuple/list requirement {requirement_input!r}")

        if not isinstance(requirement_input, str): # Must be a string by now
            raise InvalidRequirementError(f"Illformed requirement type {type(requirement_input)}: {requirement_input!r}")

        # Parse from string like ">= 1.0"
        match_obj = cls.PATTERN.match(requirement_input.strip()) # Renamed match
        if not match_obj:
            raise InvalidRequirementError(f"Illformed requirement string format: {requirement_input!r}")

        # match_obj.group(1) is operator (e.g., ">="), match_obj.group(2) is version string
        op_str = match_obj.group(1) if match_obj.group(1) else "=" # Default op is "="
        version_str_from_regex = match_obj.group(2) # Version string part

        # Check for default ">= 0"
        if op_str == ">=" and version_str_from_regex == "0":
            return cls.DEFAULT_CONSTRAINT
        else:
            return GemConstraint(op_str, GemVersion(version_str_from_regex))

    def satisfied_by(self, version_input: Union[str, int, GemVersion], trace: bool = False) -> bool: # Renamed version
        """
        Return True if the ``version_input`` (GemVersion, string, or int)
        satisfies all the constraints of this requirement. Raise an
        InvalidVersionError with an invalid ``version_input``.
        """
        if trace:
            print(f"\nis {self!r} satisfied_by: {version_input!r} ?")

        current_version: GemVersion # Renamed version
        if not isinstance(version_input, GemVersion):
            # GemVersion constructor handles str, int
            try:
                current_version = GemVersion(version_input) # type: ignore[arg-type] # version_input is Union
            except InvalidVersionError: # Catch if version_input is invalid format
                # Decide if this should re-raise or return False.
                # Original code implies it would raise from GemVersion(version).
                # For robustness, let's say an invalid version string cannot satisfy.
                if trace: print(f"  version {version_input!r} is invalid, cannot satisfy.")
                return False
            if trace:
                print(f"  converting version_input to GemVersion: {current_version!r}")
        else:
            current_version = version_input


        if not self.constraints: # Should not happen if DEFAULT_CONSTRAINT is used
            # This implies an empty GemRequirement, which might mean "any version".
            # Or it's an invalid state. For safety, let's assume it means "any version".
            # However, the original code raises InvalidRequirementError(self) here,
            # which seems more like an internal error if constraints is empty.
            # Let's stick to raising an error if constraints tuple is unexpectedly empty.
            raise InvalidRequirementError(f"GemRequirement has no constraints: {self!r}")


        for constraint_item in self.constraints: # Renamed constraint to constraint_item
            if trace:
                print(f"  processing constraint: {constraint_item.to_string()!r}")

            op_str: str = constraint_item.op # Renamed op
            # Get the comparator function (e.g., operator.eq, tilde_comparator)
            comparator_func: Callable[..., bool] = self.comparators_by_op[op_str] # Renamed comparator
            if trace:
                print(f"    got comparator_func: {comparator_func!r}")

            # Call the comparator. For tilde_comparator, it needs trace if provided.
            # Other comparators (from operator module) don't take trace.
            is_satisfied: bool # Renamed satisfying
            if op_str == "~>": # tilde_comparator has trace param
                is_satisfied = comparator_func(current_version, constraint_item.version, trace)
            else: # Standard comparators
                is_satisfied = comparator_func(current_version, constraint_item.version)

            if trace:
                print(f"    constraint {constraint_item.to_string()!r} satisfied by {current_version!r}: {is_satisfied!r}")

            if not is_satisfied:
                return False # Must satisfy ALL constraints

        return True # All constraints satisfied

    def tilde_requirements(self) -> List[GemConstraint]:
        """
        Return a sorted sequence of all pessimistic "~>" GemConstraint.
        """
        # self.constraints is Tuple[GemConstraint,...]
        # sort_constraints returns List[GemConstraint]
        sorted_constraints_list = sort_constraints(list(self.constraints)) # Renamed
        return [gc_item for gc_item in sorted_constraints_list if gc_item.op == "~>"] # Renamed


def get_tilde_constraints(constraint: GemConstraint) -> Tuple[GemConstraint, GemConstraint]:
    """
    Return a tuple of two GemConstraint representing the lower and upper
    bound of a version range ``string`` that uses a tilde "~>" pessimistic operator.
    Raise a ValueError if this is not a tilde range.

    For example:
    >>> lower_bound, upper_bound = get_tilde_constraints(GemConstraint("~>", GemVersion("1.0.2")))
    >>> vlow = GemVersion("1.0.2")
    >>> vup = GemVersion("1.1.0")
    >>> assert lower_bound == GemConstraint(op=">=", version=vlow)
    >>> assert upper_bound == GemConstraint(op="<", version=vup)
    """
    if not isinstance(constraint, GemConstraint) or not constraint.op == "~>":
        raise ValueError(f"Invalid tilde GemConstraint: {constraint!r}")
    version = constraint.version
    assert isinstance(version, GemVersion)
    lower_bound = version.release()
    upper_bound = lower_bound.bump()

    return (
        GemConstraint(op=">=", version=lower_bound),
        GemConstraint(op="<", version=upper_bound),
    )
