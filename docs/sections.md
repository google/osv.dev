# What is OSV?
---

### Introduction

OSV is a vulnerability database for open source projects. It exposes an API that
lets users of these projects query whether or not their versions are impacted.

For each vulnerability, we perform bisects to figure out the exact commit that
introduces the bug, as well the exact commit that fixes it. This is cross
referenced against upstream repositories to figure out the affected tags and
commit ranges.

### How does the API work?

The API accepts a git commit hash or a `(package, version number)` and returns the
list of vulnerabilities that are present for that version.

### Is there a rate limit?

There is a rate limit of 100 requests/min.

### Where does the data come from?

Currently, our database includes vulnerabilities from:
- [OSS-Fuzz](https://github.com/google/oss-fuzz-vulns)
- [Python](https://github.com/pypa/advisory-db)
- [Go](https://github.com/golang/vulndb)
- [Rust](https://github.com/RustSec/advisory-db)
- [GSD](https://github.com/cloudsecurityalliance/gsd-database)
- npm (from GitHub Security Advisories).
- Maven (from GitHub Security Advisories).

These are all vulnerability databases that have adopted the [OpenSSF Open
Source Vulnerability format](https://ossf.github.io/osv-schema/), making it
easier to work with vulnerabilities in an ecosystem independent way.

The full list of vulnerabilities can be browsed at <https://osv.dev>.

# Getting Started
---

### Using the API

Browse the reference section of this site to see examples of what you can do
with this API and how to use it.

For some quick examples, run:

```
curl -X POST -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
    "https://api.osv.dev/v1/query"
```

```
curl -X POST -d \
          '{"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
          "https://api.osv.dev/v1/query"
```
