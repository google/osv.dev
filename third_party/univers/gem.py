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

import operator
import re
from collections import namedtuple
from itertools import dropwhile


class InvalidRequirementError(AttributeError):
    pass


class InvalidVersionError(ValueError):
    pass


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

    VERSION_PATTERN = r"[0-9]+(?:\.[0-9a-zA-Z]+)*(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?"
    is_correct = re.compile(rf"^\s*({VERSION_PATTERN})?\s*$").match

    def __init__(self, version):
        """
        Construct a Version from the ``version`` string.  A version string is a
        series of digits or ASCII letters separated by dots and may contain dash
        "-".
        """
        if isinstance(version, (int, GemVersion)):
            version = str(version)

        if not isinstance(version, str):
            raise InvalidVersionError(version)

        if not self.is_correct(version):
            raise InvalidVersionError(version)

        # If version is an empty string convert it to 0
        version = str(version).strip()

        self.original = version

        if not version:
            version = "0"

        self.version = version.replace("-", ".pre.")
        self._segments = ()
        self._canonical_segments = ()
        self._bump = None
        self._release = None

    def __str__(self):
        return self.original

    to_string = __str__

    def __repr__(self):
        return f"GemVersion({self.original!r})"

    def equal_strictly(self, other):
        return self.version == other.version

    def __hash__(self):
        return hash(self.canonical_segments)

    def __eq__(self, other):
        return self.canonical_segments == other.canonical_segments

    def __lt__(self, other):
        return self.__cmp__(other) < 0

    def __le__(self, other):
        return self.__cmp__(other) <= 0

    def __gt__(self, other):
        return self.__cmp__(other) > 0

    def __ge__(self, other):
        return self.__cmp__(other) >= 0

    def bump(self):
        """
        Return a new version object where the next to the last revision number
        is one greater (e.g., 5.3.1 => 5.4) i.e., incrementing this GemVersion
        last numeric segment.

        For example::
        >>> assert GemVersion("5.3.1").bump() == GemVersion("5.4"), repr(GemVersion("5.3.1").bump())
        >>> assert GemVersion("5.3.1.4-2").bump() == GemVersion("5.3.2"), GemVersion("5.3.1.4-2").bump()
        """
        if not self._bump:
            segments = []
            for seg in self.segments:
                if isinstance(seg, str):
                    break
                else:
                    segments.append(seg)

            if len(segments) > 1:
                segments.pop()

            segments[-1] += 1
            segments = [str(r) for r in segments]
            self._bump = GemVersion(".".join(segments))

        return self._bump

    def release(self):
        """
        Return a new GemVersion which is the release for this version (e.g.,
        1.2.0.a -> 1.2.0). Non-prerelease versions return themselves. A release
        is composed only of numeric segments.
        """
        if not self._release:
            if self.prerelease():
                segments = self.segments
                while any(isinstance(s, str) for s in segments):
                    segments.pop()
                segments = (str(s) for s in segments)
                self._release = GemVersion(".".join(segments))
            else:
                self._release = self

        return self._release

    def prerelease(self):
        """
        Return True if this is considered as a prerelease version.
        A version is considered a prerelease if it contains a letter.
        """
        return any(not str(s).isdigit() for s in self.segments)

    @property
    def segments(self):
        """
        Return a new sequence of segments for this version where segments are
        ints or strings parsed from the original version string.
        """
        if not self._segments:
            self._segments = self.get_segments()
        return list(self._segments)

    def get_segments(self):
        """
        Return a sequence of segments for this version where segments are ints
        or strings parsed from the original version string.
        """
        find_segments = re.compile(r"[0-9]+|[a-z]+", re.IGNORECASE).findall
        segments = []
        for seg in find_segments(self.version):
            if seg.isdigit():
                seg = int(seg)
            segments.append(seg)
        return tuple(segments)

    @property
    def canonical_segments(self):
        if not self._canonical_segments:
            self._canonical_segments = self.get_canonical_segments()
        return list(self._canonical_segments)

    def get_canonical_segments(self):
        """
        Return a new sequence of "canonical segments" for this version using
        the Rubygems way.
        """
        canonical_segments = []
        for segments in self.split_segments():
            segs = list(dropwhile(lambda s: s == 0, reversed(segments)))
            segs = reversed(segs)
            canonical_segments.extend(segs)
        return tuple(canonical_segments)

    def split_segments(self):
        """
         Return a two-tuple of segments:
        - the first is a list of numeric-only segments starting from the left
        - the second is a list of alpha or numericsegments starting with the
          first alpha segment from the left.
        """
        numeric_segments = []
        string_segments = []
        for seg in self.segments:
            is_numeric = isinstance(seg, int)  # or (isinstance(seg, str) and seg.isdigit())
            if is_numeric:
                if string_segments:
                    string_segments.append(seg)
                else:
                    numeric_segments.append(seg)
            else:
                string_segments.append(seg)
        return numeric_segments, string_segments

    def __cmp__(self, other, trace=False):
        """
        Compare this version with ``other`` returning -1, 0, or 1 if the
        other version is larger, the same, or smaller than this
        one. Attempts to compare to something that's not a
        ``GemVersion raises an exception.

        The comparison results have the same semantics as the legacy "cmp()"
        built-in function.
        """
        if trace:
            print(f"\nComparing: {self!r} with {other!r}")
        if isinstance(other, str):
            other = GemVersion(other)
            if trace:
                print(f"  Converted to GemVersion: {other!r}")

        if not isinstance(other, GemVersion):
            if trace:
                print(f"  Not a GemVersion: {other!r}")
            return

        if self.version == other.version:
            return 0

        lhsegments = self.canonical_segments
        if trace:
            print(f"  lhsegments: canonical_segments: {lhsegments!r}")

        rhsegments = other.canonical_segments
        if trace:
            print(f"  rhsegments: canonical_segments: {rhsegments!r}")

        if lhsegments == rhsegments:
            if trace:
                print(f"    lhsegments == rhsegments: returning 0")
            return 0

        lhsize = len(lhsegments)
        rhsize = len(rhsegments)
        if trace:
            print(f"  lhsize: {lhsize!r}")
        if trace:
            print(f"  rhsize: {rhsize!r}")

        if lhsize > rhsize:
            if trace:
                print(f"  lhsize > rhsize: limit = lhsize: {lhsize!r}")
            limit = lhsize
        else:
            if trace:
                print(f"  lhsize <= rhsize: limit = rhsize: {rhsize!r}")
            limit = rhsize

        limit -= 1

        i = 0

        if trace:
            print(f"  limit: {limit!r}, i: {i!r}")

        while i <= limit:
            if trace:
                print(f"    limit: {limit!r}, i: {i!r}")

            try:
                lhs = lhsegments[i]
            except IndexError:
                lhs = 0

            try:
                rhs = rhsegments[i]
            except IndexError:
                rhs = 0

            i += 1

            if trace:
                print(f"      lhs: {lhs} rhs: {rhs} i: {i!r}")

            if lhs == rhs:
                if trace:
                    print(f"      lhs == rhs: continue")
                continue

            if isinstance(lhs, str) and isinstance(rhs, int):
                if trace:
                    print(f"      isinstance(lhs, str): {type(lhs)!r}")
                    print(f"      isinstance(rhs, int): {type(rhs)!r}")
                    print(f"      return -1")
                return -1

            if isinstance(lhs, int) and isinstance(rhs, str):
                if trace:
                    print(f"      isinstance(lhs, int): {type(lhs)!r}")
                    print(f"      isinstance(rhs, str): {type(rhs)!r}")
                    print(f"      return 1")
                return 1

            result = (lhs > rhs) - (lhs < rhs)
            if trace:
                print(f"      (lhs > rhs) - (lhs < rhs):{result!r}")
                print(f"      return {result}")

            return result

        if trace:
            print(f"  all options evaluated: return 0")
        return 0


GemConstraint = namedtuple("GemConstraint", ["op", "version"])
GemConstraint.to_string = lambda gc: f"{gc.op} {gc.version}"


def sort_constraints(constraints):
    """
    Return a sorted sequence of unique GemConstraints.
    """
    constraints = sorted(constraints, key=lambda gc: (gc.version, gc.op))
    consts = []
    for gc in constraints:
        if gc in consts:
            continue
        consts.append(gc)
    return consts


def tilde_comparator(version, requirement, trace=False):
    """
    Return True if ``version`` GemVersion satisfies ``requirement`` GemVersion
    according to the Rubygems tilde semantics.
    """
    if trace:
        print(f"      tilde_comparator: version: {version!r}, requirement: {requirement!r}")
        print(f"         version >= requirement: {version >= requirement!r}")
        print()
        print(
            f"         version.release() < requirement.bump(): {version.release()!r} "
            f"< {requirement.bump()!r}: {version.release() < requirement.bump()!r}"
        )

    return version >= requirement and version.release() < requirement.bump()


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

    PATTERN_RAW = f"\\s*({quoted})?\\s*({GemVersion.VERSION_PATTERN})\\s*"

    # A regular expression that matches a requirement
    PATTERN = re.compile(f"^{PATTERN_RAW}$")

    # The default requirement matches any version
    DEFAULT_CONSTRAINT = GemConstraint(">=", GemVersion(0))

    def __init__(self, *requirements):
        """
        Initialize a GemRequirement from a sequence of ``requirements``
        converted to a constraints sequence of GemConstraint.
        """
        if not requirements:
            self.constraints = (GemRequirement.DEFAULT_CONSTRAINT,)
        else:
            self.constraints = tuple([GemRequirement.parse(r) for r in requirements])

    def __str__(self):
        gcs = [gc.to_string() for gc in sort_constraints(self.constraints)]
        return ", ".join(gcs)

    def __repr__(self):
        gcs = ", ".join(repr(gc.to_string()) for gc in sort_constraints(self.constraints))
        return f"GemRequirement({gcs})"

    @classmethod
    def from_string(cls, requirements):
        """
        Return a GemRequirement build from a lockfile-style ``requirements``
        string.

        For example::
        >>> gr1 = GemRequirement(">= 1.0.1", "~> 1.0")
        >>> gr2 = GemRequirement.from_string(" (>= 1.0.1, ~> 1.0)")
        >>> assert gr1 == gr2, (gr1, gr2)
        """
        reqs = requirements.strip().strip("()")
        reqs = [r.strip() for r in reqs.split(",")]
        return cls(*reqs)

    def for_lockfile(self):
        """
        Return a string representing this list of requirements suitable for use
        in a lockfile.

        For example::
        >>> gr = GemRequirement(">= 1.0.1", "~> 1.0")
        >>> gf_flf = gr.for_lockfile()
        >>> assert gf_flf == " (~> 1.0, >= 1.0.1)", gf_flf
        """
        gcs = [gc.to_string() for gc in sort_constraints(self.constraints)]
        gcs = ", ".join(gcs)
        return f" ({gcs})"

    def dedupe(self):
        """
        Return a new GemRequirement with sorted and unique constraints.
        """
        return GemRequirement(*sort_constraints(self.constraints))

    def simplify(self):
        """
        Return a new simplified GemRequirement with:
        - sorted and unique constraints.
        - where ~> constraints are replaced by simpler contrainsts.
        """
        constraints = []
        for const in self.constraints:
            if const.op == "~>":
                low_high = get_tilde_constraints(const)
                constraints.extend(low_high)
            else:
                constraints.append(const)
        return GemRequirement(*sort_constraints(constraints))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False

        # An == check is always necessary
        if sort_constraints(self.constraints) == sort_constraints(other.constraints):
            stilde = self.tilde_requirements()
            if not stilde:
                # An == check is sufficient unless any requirements use ~>
                return True
            else:
                # If any requirements use ~> we use the stricter `#eql?` that
                # also checks that version precision is the same
                otilde = other.tilde_requirements()
                if len(stilde) != len(otilde):
                    return False
                for st, ot in zip(stilde, otilde):
                    if st.op != ot.op or not st.version.equal_strictly(ot.version):
                        return False
                return True
        return False

    def exact(self):
        """
        Return True if the requirement is for only an exact version.

        For example:
        >>> GemRequirement(">= 1.0.1", "~> 1.0").exact()
        False
        >>> GemRequirement("= 1.0.1", "~> 1.0").exact()
        False
        >>> GemRequirement("= 1.0.1").exact()
        True
        """
        return len(self.constraints) == 1 and self.constraints[0].op == "="

    @classmethod
    def create(cls, reqs):
        """
        Return a GemRequirement built from a single requirement string or a list
        of requirement strings.
        """
        if isinstance(reqs, list):
            return cls(*reqs)
        else:
            return cls(reqs)

    @classmethod
    def parse(cls, requirement):
        """
        Return a GemConstraint tuple of (operator string, GemVersion object)
        parsed from a single ``requirement`` string such as "> 3.0". Also
        accepts a two-tuple or list of ("op", "version") or a single GemVersion or a
        GemConstraint).
        """
        if isinstance(requirement, GemVersion):
            return GemConstraint("=", requirement)

        if isinstance(requirement, (tuple, list, GemConstraint)):
            return GemConstraint(*requirement)

        if not isinstance(requirement, str):
            raise InvalidRequirementError("Illformed requirement {requirement!r}")

        match = cls.PATTERN.match(str(requirement))
        if not match:
            raise InvalidRequirementError("Illformed requirement {requirement!r}")

        if match.group(1) == ">=" and match.group(2) == "0":
            return cls.DEFAULT_CONSTRAINT
        else:
            op = match.group(1) if match.group(1) else "="
            return GemConstraint(op, GemVersion(match.group(2)))

    def satisfied_by(self, version, trace=False):
        """
        Return True if the ``version`` GemVersion or version string or int
        satisfies all the constraints of this requirement. Raise an
        InvalidVersionError with an invalid ``version``.
        """
        if trace:
            print(f"\nis {self!r} satisfied_by: {version!r} ?")
        if not isinstance(version, GemVersion):
            version = GemVersion(version)
            if trace:
                print(f" converting version to GemVersion: {version!r}")

        if not self.constraints:
            raise InvalidRequirementError(self)

        for constraint in self.constraints:
            if trace:
                print(f"  processing: {constraint!r}")

            op = constraint.op
            comparator = self.comparators_by_op[op]
            if trace:
                print(f"    got comparator: {comparator!r}")
            satisfying = comparator(version, constraint.version)
            if trace:
                print(f"    {self!r} is satisfied by: {version!r}: {satisfying!r}")
                print(f"    {version!r} {op} {constraint.version!r}: {satisfying!r}")
            if not satisfying:
                return False

        return True

    def tilde_requirements(self):
        """
        Return a sorted sequence of all pessimistic "~>" GemConstraint.
        """
        constraints = sort_constraints(self.constraints)
        return [gc for gc in constraints if gc.op == "~>"]


def get_tilde_constraints(constraint):
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
