## Why did you create OSV?

We created OSV initially for our [OSS-Fuzz](https://github.com/google/oss-fuzz) service, where we needed a way to store, track and query the large numbers of security bugs we find and reproduce in open source software in an automated fashion. We understand that fuzzing is not the only way vulnerabilities are discovered, so we're hoping to expand the data sources tracked by OSV in the future.

## How does OSV compare to the existing CVE process?

OSV complements the existing CVE process. We plan to automatically include CVE data in OSV for the cases where we have information on when a vulnerability was introduced into the source or can automatically reproduce it. The goal of OSV is to provide OSS consumers with precise vulnerability metadata in an easy-to-query database (using either package versions or commits). So, this will make CVE vulnerabilities easier to query and faster to adopt. Currently, OSV provides access to thousands of vulnerabilities found by our OSS-Fuzz fuzzing service. In near future, OSV plans to aggregate vulnerabilities from other data sources, e.g. direct developer input and package managers.

## Where does the data come from?

Currently, our data aggregates [thousands of vulnerabilities](https://bugs.chromium.org/p/oss-fuzz/issues/list?q=Type%3DBug-Security%20-status%3AWontFix%2CDuplicate&can=1) found via fuzzing
[380+ open source projects](https://github.com/google/oss-fuzz/tree/master/projects)
integrated with
[OSS-Fuzz](https://github.com/google/oss-fuzz). We are planning to work with the
open source community to expand this to various language ecosystems.

## How can I help onboard a new source of data?

Please let us know of your interest via either our [issue tracker](https://github.com/google/osv/issues)
or the [mailing list](mailto:osv-discuss@googlegroups.com). We are looking for data sources that can provide precise information on where the bug was introduced and where it got fixed (via versions / tags or commits or both). If this information is not available, we need a reproducer testcase to accurately determine this via build bisection. Our goal is to provide [easy access](https://osv.dev/docs/#tag/api) to actionable vulnerabilities in a fully automated way.
 
## How do you determine the introduced in / fixed in commits?

We perform bisections using the reproduction testcase and package binary to determine these values.

## What does it mean when an introduced in / fixed in commit is a range?

Bisection may fail in some cases (e.g. build failures or reproduction flakes) and
we may show a narrow range "A:B" of commits instead of an exact commit. This means that the result lies in the range of commits from A (exclusive) to B (inclusive).

## Which version control systems (VCS) do you support?

Our efforts are currently focused on projects that use git. Support for other
popular version control systems will be added as we get cycles.

## I'm a project maintainer. Can I edit the details of OSV entries for my project?

We are working on a way for project maintainers to edit relevant OSV vulnerabilities. Please subscribe to our [mailing list](mailto:osv-discuss@googlegroups.com) for updates on this.

## Will I be able to see bugs that don’t have a fix yet?

We comply with the OSS-Fuzz vulnerability disclosure policy, either 90 days from report or 30 days after a fix is checked in, whichever comes earlier. The vulnerabilities are hidden until the disclosure timeline is met.
