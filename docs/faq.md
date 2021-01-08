## Where does the data come from?

Currently, our data comes from
[380+ open source projects](https://github.com/google/oss-fuzz/tree/master/projects)
integrated with
[OSS-Fuzz](https://github.com/google/oss-fuzz). We are planning to work with the
open source community to expand this to other ecosytems.

## How can I help onboard a new source of data?

We are finalizing the details of this, but please let us know of your interest
via either our [issue tracker](https://github.com/google/osv/issues) or
[mailing list](mailto:osv-discuss@googlegroups.com)!

## How do you obtain the introduced in / fixed in commits?

We perform bisects to determine these.

## What does it mean when an introduced in / fixed in commit is a range?

Bisection may fail in some cases (e.g. build failures or reproduction flake) and
we may show a narrow range "A:B" of commits instead. This means the range of
commits from A (exclusive) to B (inclusive).

## I'm a project maintainer. Can I edit the details of OSV entries for my project?

We are working on a way for project maintainers to edit relevant OSV
vulnerabilities.
