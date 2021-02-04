## Why did you create OSV?

We created OSV to address some of the shortcomings of dealing with
vulnerabilities in open source software.

As believers of automation, we initially built OSV for our
[OSS-Fuzz](https://github.com/google/oss-fuzz) service, where we needed a way to
store, triage and query the large numbers of open source vulnerabilities we
discover in an automated fashion.

We understand that fuzzing is not the only way vulnerabilities are discovered,
and we plan to [extend our data with other sources](https://github.com/google/osv/issues/44)
by working with open source communities.

## Who is OSV for?

OSV can be used by both:

- Open source consumers: By querying our API to find vulnerabilities in their
  dependencies.

- Open source maintainers: By using our bisection and triage infrastructure to
  determine accurate affected commits and versions when a vulnerability is
  fixed.

## How does OSV compare to the existing CVE process?

We plan to aggregate existing vulnerabilities feeds (such as CVEs). OSV
complements CVEs by extending them with precise vulnerability metadata and
making it easier to query for them (using either package versions or commits).

## Where does the data come from?

Currently, our data aggregates [thousands of vulnerabilities](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=Type%3DBug-Security%20-status%3AWontFix%2CDuplicate&can=1) found via fuzzing
[380+ open source projects](https://github.com/google/oss-fuzz/tree/master/projects)
integrated with
[OSS-Fuzz](https://github.com/google/oss-fuzz). We are planning to work with the
open source community to
[expand this to various package ecosystems](https://github.com/google/osv/issues/44).

## How are vulnerabilities represented?

All our vulnerabilities are described in a [simple format] easily used by
automation tools. This format is also intended to be easily human-editable and
used for interoperability with vulnerability sources.

[simple format]: https://osv.dev/docs/#tag/vulnerability_schema

## How can I help onboard a new source of data?

Please let us know of your interest via either our [issue tracker](https://github.com/google/osv/issues)
or the [mailing list](mailto:osv-discuss@googlegroups.com).

The pipeline for this is still in progress (and open to feedback). You can
follow along on how this might look at at <https://github.com/google/osv/issues/44>.

We are looking for data sources that can provide:
- Precise commit-level information on where vulnerability was introduced and where it got fixed (preferred).
- Or a list of affected versions / tags.

If this information is not available, our infrastruture will require a reproducer
testcase to accurately determine this via build bisection. Our goal is to
provide [easy access](https://osv.dev/docs/#tag/api) to actionable
vulnerabilities in a fully automated way.

## How do you determine the introduced in / fixed in commits?

We perform bisections using the reproduction testcase and package binary to determine these values.

## What does it mean when an introduced in / fixed in commit is a range?

Bisection may fail in some cases (e.g. build failures or reproduction flakes) and
we may show a narrow range "A:B" of commits instead of an exact commit. This means that the result lies in the range of commits from A (exclusive) to B (inclusive).

## What if it's not feasible to compute the introduced in / fixed in commits?

We encourage all vulnerabilities to have reproduction steps and/or precise
commit level details where possible. However we understand that in some cases
and package ecosystems this is not feasible at scale and does not provide as
much value.

In these cases [Vulnerabilities] may omit the affected commit ranges and
only specify a list of affected versions instead.

[Vulnerabilities]: https://osv.dev/docs/#tag/vulnerability_schema

## Which version control systems (VCS) do you support?

Our efforts are currently focused on projects that use git. Support for other
popular version control systems will be added as we get cycles.

## I'm a project maintainer. Can I edit the details of OSV entries for my project?

We are working on a way for project maintainers to edit relevant OSV vulnerabilities. Please subscribe to our [mailing list](mailto:osv-discuss@googlegroups.com) for updates on this.

## Will I be able to see bugs that don’t have a fix yet?

We comply with the OSS-Fuzz vulnerability disclosure policy, either 90 days from report or 30 days after a fix is checked in, whichever comes earlier. The vulnerabilities are hidden until the disclosure timeline is met.
