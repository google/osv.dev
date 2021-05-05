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

The API accepts a git commit hash or a version number and returns the
list of vulnerabilities that are present for that version.

### Is there a rate limit?

There is a rate limit of 100 requests/min.

### Where does the data come from?

This is currently filled with vulnerabilities found by [OSS-Fuzz] (mostly C/C++
projects). OSS-Fuzz is a continuous fuzzing service for open source software,
with over 350 open source projects integrated and has found over [25,000] bugs.
This will be extended in the future to
[support other vulnerability sources](https://github.com/google/osv/issues/44).

The full list of vulnerabilities can be browsed at <https://osv.dev>.

[OSS-Fuzz]: https://github.com/google/oss-fuzz
[25,000]: https://bugs.chromium.org/p/oss-fuzz/issues/list?q=-status%3AWontFix%2CDuplicate%20-component%3AInfra&can=1

# Getting Started
---

### Using the API

Browse the reference section of this site to see examples of what you can do
with this API and how to use it.

For a quick example using curl, run:

```
curl -X POST -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
    "https://api.osv.dev/v1/query"
```

Note that the format of the JSON returned is not yet stable and may be subject
to minor changes.
