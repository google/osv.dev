#
# Copyright (c) SAS Institute Inc.
# Copyright (c) Facebook, Inc. and its affiliates.
#
# SPDX-License-Identifier: MIT AND Apache-2.0
# Version comparison utility extracted from python-rpm-vercmp and further
# stripped down and significantly modified from the original at python-rpm-vercmp
# Also includes updates from Facebook antlir merged in.
#
# Visit https://aboutcode.org and https://github.com/nexB/univers for support and download.

from __future__ import annotations

import re
from typing import Any, ClassVar, Match, NamedTuple, Optional, Pattern, Tuple, Type, Union


class RpmVersion(NamedTuple):
    """
    Represent an RPM version. It is ordered.
    """

    epoch: int
    version: str # Main version string, e.g., "1.2.3"
    release: str # Release string, e.g., "1.el7"

    # The *args, **kwargs in __str__ are unusual for a simple __str__ override.
    # They might be there for a specific reason (e.g. subclassing or specific dispatcher)
    # or could be removed if not needed. Keeping them for now to match original.
    def __str__(self, *args: Any, **kwargs: Any) -> str:
        return self.to_string()

    def to_string(self) -> str:
        version_release_part: str # Renamed vr
        if self.release: # If release is non-empty
            version_release_part = f"{self.version}-{self.release}"
        else: # No release part
            version_release_part = self.version

        if self.epoch != 0: # Only prepend epoch if it's non-zero
            return f"{self.epoch}:{version_release_part}"
        return version_release_part

    @classmethod
    def from_string(cls: Type[RpmVersion], s: str) -> RpmVersion:
        # s.strip() was here, but from_evr also does s.strip() effectively if s is the full EVR.
        # If s is just part of it, stripping here might be useful.
        # However, from_evr is designed to parse the EVR string.
        # Let's rely on from_evr to handle string parsing.
        e, v, r = from_evr(s) # from_evr returns Tuple[int, str, str]
        return cls(e, v, r)

    # For rich comparison methods, `other` should ideally be `object` for proper override.
    # The comparison logic delegates to `compare_rpm_versions` which handles
    # `Union[RpmVersion, str]`. This is fine.
    def __lt__(self, other: object) -> bool:
        if not isinstance(other, (RpmVersion, str)):
            return NotImplemented
        return compare_rpm_versions(self, other) < 0

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, (RpmVersion, str)):
            return NotImplemented
        return compare_rpm_versions(self, other) > 0

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, (RpmVersion, str)):
            return NotImplemented
        return compare_rpm_versions(self, other) == 0

    def __le__(self, other: object) -> bool:
        if not isinstance(other, (RpmVersion, str)):
            return NotImplemented
        return compare_rpm_versions(self, other) <= 0

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, (RpmVersion, str)):
            return NotImplemented
        return compare_rpm_versions(self, other) >= 0


def from_evr(s: str) -> Tuple[int, str, str]:
    """
    Return an (Epoch, Version, Release) tuple given a version string ``s`` by
    splitting "[E:]V-R" into the three possible subcomponents.
    Default epoch to 0. Version and Release default to an empty string if not
    specified.

    For example:
    >>> assert from_evr("1:11.13.2.0-1") == (1, "11.13.2.0", "1")
    >>> assert from_evr("11.13.2.0-1") == (0, "11.13.2.0", "1")
    >>> assert from_evr("11.13.2.0") == (0, "11.13.2.0", "")
    >>> assert from_evr("1:11.13.2.0") == (1, "11.13.2.0", "")
    >>> assert from_evr("foo") == (0, "foo", "")
    >>> assert from_evr("1:foo") == (1, "foo", "")
    >>> assert from_evr(":foo") == (0, "foo", "") # epoch cannot be empty if : present
    >>> assert from_evr("1:") == (1, "", "")
    """
    s = s.strip() # Ensure no leading/trailing whitespace affect parsing

    epoch_str: str
    version_release_part: str # Renamed vr

    if ":" in s:
        epoch_str, _, version_release_part = s.partition(":")
        # RPM spec: if epoch is present but empty (e.g. ":1.0-1"), it's invalid or treated as 0.
        # Python's int('') raises ValueError. Let's ensure epoch_str is valid or default.
        if not epoch_str: # Handles ":version-release" case
            epoch_val = 0
        else:
            try:
                epoch_val = int(epoch_str)
            except ValueError:
                # Or raise error, depending on how strict this parser should be.
                # RPM itself might error on invalid epoch. Assuming 0 for ill-formed.
                epoch_val = 0
    else:
        epoch_val = 0
        version_release_part = s

    version_part: str # Renamed v
    release_part: str # Renamed r
    # RPM spec: version-release. Release is optional. Hyphen is the delimiter.
    # Version part cannot be empty. Release part can be empty.
    if "-" in version_release_part:
        # Use rpartition for cases like "foo-bar-baz", where version is "foo-bar", release is "baz"
        version_part, _, release_part = version_release_part.rpartition("-")
    else:
        version_part = version_release_part
        release_part = "" # No release part

    return epoch_val, version_part, release_part


def compare_rpm_versions(a: Union[RpmVersion, str], b: Union[RpmVersion, str]) -> int:
    """
    Compare two RPM versions ``a`` and ``b`` and return:
    -  1 if the version of a is newer than b
    -  0 if the versions match
    -  -1 if the version of a is older than b

    These are the legacy "cmp()" function semantics.

    This implementation is adapted from both this blog post:
    https://blog.jasonantman.com/2014/07/how-yum-and-rpm-compare-versions/
    and this Apache 2 licensed implementation:
    https://github.com/sassoftware/python-rpm-vercmp/blob/master/rpm_vercmp/vercmp.py

    For example::
    >>> assert compare_rpm_versions("1.0", "1.1") == -1
    >>> assert compare_rpm_versions("1.1", "1.0") == 1
    >>> assert compare_rpm_versions("11.13.2-1", "11.13.2.0-1") == -1
    >>> assert compare_rpm_versions("11.13.2.0-1", "11.13.2-1") == 1
    """
    # Coerce inputs to RpmVersion objects if they are strings
    rpm_a: RpmVersion = RpmVersion.from_string(a) if isinstance(a, str) else a
    rpm_b: RpmVersion = RpmVersion.from_string(b) if isinstance(b, str) else b

    # After coercion, both must be RpmVersion instances.
    # This check is more for internal consistency / type refinement if needed,
    # as from_string should produce RpmVersion or raise error.
    # The Union type hint already covers this, but explicit check can be useful.
    if not isinstance(rpm_a, RpmVersion) or not isinstance(rpm_b, RpmVersion):
        # This should ideally not be reached if inputs conform to Union type hint
        # and RpmVersion.from_string works as expected.
        raise TypeError(f"Inputs must be RpmVersion or string: got {type(a)}, {type(b)}")

    # First compare the epoch. If epochs are different, that determines order.
    if rpm_a.epoch != rpm_b.epoch:
        return 1 if rpm_a.epoch > rpm_b.epoch else -1

    # Epochs are the same. Compare version strings.
    # vercmp (the Vercmp.compare based one) is used for version and release parts.
    version_compare_res: int = vercmp(rpm_a.version, rpm_b.version) # Renamed compare_res
    if version_compare_res != 0:
        return version_compare_res

    # Versions are also the same. Compare release strings.
    return vercmp(rpm_a.release, rpm_b.release)


class Vercmp:
    # Regex patterns are compiled for bytes
    R_NONALNUMTILDE_CARET: ClassVar[Pattern[bytes]] = re.compile(rb"^([^a-zA-Z0-9~\^]*)(.*)$")
    R_NUM: ClassVar[Pattern[bytes]] = re.compile(rb"^([\d]+)(.*)$")
    R_ALPHA: ClassVar[Pattern[bytes]] = re.compile(rb"^([a-zA-Z]+)(.*)$")

    @classmethod
    def compare(cls: Type[Vercmp], first_str: str, second_str: str) -> int: # Renamed first, second
        # Rpm versions can only be ascii, anything else is just ignored
        first_bytes: bytes = first_str.encode("ascii", "ignore") # Renamed first
        second_bytes: bytes = second_str.encode("ascii", "ignore") # Renamed second

        if first_bytes == second_bytes:
            return 0

        while first_bytes or second_bytes:
            # Strip leading non-alphanumeric characters (except tilde and caret)
            # These regexes operate on bytes.
            match1_nonalnum: Optional[Match[bytes]] = cls.R_NONALNUMTILDE_CARET.match(first_bytes)
            match2_nonalnum: Optional[Match[bytes]] = cls.R_NONALNUMTILDE_CARET.match(second_bytes)

            # Should always match due to (.*)
            if not match1_nonalnum or not match2_nonalnum: # Should not happen
                # This implies an issue with the regex or input that wasn't caught.
                # For robustness, treat as equal if regex fails unexpectedly, or raise.
                break

            # head1/2 is the junk prefix, first/second_bytes becomes the rest
            head1, first_bytes = match1_nonalnum.groups()
            head2, second_bytes = match2_nonalnum.groups()

            if head1 or head2: # If there was a junk prefix, ignore it and restart loop iteration
                continue

            # Handle tilde separator: sorts before everything else
            if first_bytes.startswith(b"~"):
                if not second_bytes.startswith(b"~"): return -1 # first is older
                first_bytes, second_bytes = first_bytes[1:], second_bytes[1:]
                continue
            if second_bytes.startswith(b"~"): return 1 # second is older

            # Handle caret separator: similar to tilde but different semantics for end of string
            if first_bytes.startswith(b"^"):
                if not second_bytes: return 1  # first has caret, second ended: first > second
                if not second_bytes.startswith(b"^"): return -1  # first has caret, second non-caret: first < second
                first_bytes, second_bytes = first_bytes[1:], second_bytes[1:] # Both have caret, strip and continue
                continue
            if second_bytes.startswith(b"^"): # Only second has caret
                return -1 if first_bytes else 1 # second < first (if first not ended), or second > first (if first ended)


            # If either string is now empty, the loop should terminate
            if not first_bytes or not second_bytes:
                break

            # Extract first segment (all alpha or all numeric)
            is_num_segment: bool # Renamed isnum

            match1_seg: Optional[Match[bytes]] = cls.R_NUM.match(first_bytes) # Renamed m1
            if match1_seg: # first_bytes starts with a number
                match2_seg: Optional[Match[bytes]] = cls.R_NUM.match(second_bytes) # Renamed m2
                if not match2_seg: return 1 # Numeric segments are newer than alpha segments
                is_num_segment = True
            else: # first_bytes starts with alpha (or is empty, handled by loop cond)
                match1_seg = cls.R_ALPHA.match(first_bytes)
                if not match1_seg : # Should not happen if first_bytes is not empty and not junk
                     break # Or handle as error
                match2_seg = cls.R_ALPHA.match(second_bytes)
                if not match2_seg: return -1 # Alpha segments are older than numeric segments
                is_num_segment = False

            if not match1_seg or not match2_seg : # Should not happen if logic above is correct
                break # Error or unexpected state

            # Get the actual segment and the rest of the string
            seg1_bytes, first_bytes = match1_seg.groups() # Renamed m1_head
            seg2_bytes, second_bytes = match2_seg.groups() # Renamed m2_head

            if is_num_segment:
                seg1_bytes = seg1_bytes.lstrip(b"0")
                seg2_bytes = seg2_bytes.lstrip(b"0")
                len_seg1 = len(seg1_bytes) # Renamed m1hlen
                len_seg2 = len(seg2_bytes) # Renamed m2hlen
                if len_seg1 < len_seg2: return -1
                if len_seg1 > len_seg2: return 1

            # Compare segments (lexicographically for alpha, or numerically by string for numbers of same length)
            if seg1_bytes < seg2_bytes: return -1
            if seg1_bytes > seg2_bytes: return 1
            # Segments are equal, continue loop with remaining parts

        # Loop ended. Check if one string has remaining parts.
        len_first_bytes = len(first_bytes) # Renamed m1len
        len_second_bytes = len(second_bytes) # Renamed m2len
        if len_first_bytes == 0 and len_second_bytes == 0: return 0
        if len_first_bytes != 0: return 1 # first_bytes has remaining parts, so it's "larger"
        return -1 # second_bytes has remaining parts, so it's "larger" (making first_bytes "smaller")


def vercmp(first: str, second: str) -> int:
    return Vercmp.compare(first, second)