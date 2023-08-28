---
layout: page
title: Data sources
permalink: /data/
nav_order: 3
---
# Data sources
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Current data sources  
  
**This is an ongoing project.**  
We encourage open source ecosystems to adopt the
[Open Source Vulnerability format](https://ossf.github.io/osv-schema/) to enable
open source users to easily aggregate and consume vulnerabilities across all
ecosystems. See our
[blog post](https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html)
for more details.

The following ecosystems have vulnerabilities encoded in this format:

-   [GitHub Advisory Database](https://github.com/github/advisory-database)
    ([CC-BY 4.0](https://github.com/github/advisory-database/blob/main/LICENSE.md))
-   [PyPI Advisory Database](https://github.com/pypa/advisory-database)
    ([CC-BY 4.0](https://github.com/pypa/advisory-database/blob/main/LICENSE))
-   [Go Vulnerability Database](https://github.com/golang/vulndb)
    ([CC-BY 4.0](https://github.com/golang/vulndb#license))
-   [Rust Advisory Database](https://github.com/RustSec/advisory-db)
    ([CC0 1.0](https://github.com/rustsec/advisory-db/blob/main/LICENSE.txt))
-   [Global Security Database](https://github.com/cloudsecurityalliance/gsd-database)
    ([CC0 1.0](https://github.com/cloudsecurityalliance/gsd-database/blob/main/LICENSE))
-   [OSS-Fuzz](https://github.com/google/oss-fuzz-vulns)
    ([CC-BY 4.0](https://github.com/google/oss-fuzz-vulns/blob/main/LICENSE))

## Converted data
Additionally, the OSV.dev team maintains a conversion pipeline for:

-   [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html),
    using the conversion tools
    [here](https://github.com/ossf/osv-schema/tree/main/tools/debian).
-   [Alpine SecDB](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/),
    using the conversion tools
    [here](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/alpine).

## Covered Ecosystems
Between the data served in OSV and the data converted to OSV the following ecosystems are covered.

-   AlmaLinux
-   Alpine
-   Android
-   crates.io
-   Debian GNU/Linux
-   GitHub Actions
-   Go
-   Hex
-   Linux kernel
-   Maven
-   npm
-   NuGet
-   OSS-Fuzz
-   Packagist
-   Pub
-   PyPI
-   Rocky Linux
-   RubyGems

## Data dumps

For convenience, these sources are aggregated and continuously exported to a GCS
bucket maintained by OSV:
[`gs://osv-vulnerabilities`](https://osv-vulnerabilities.storage.googleapis.com)

This bucket contains individual entries of the format
`gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json` as well as a zip containing all
vulnerabilities for each ecosystem at
`gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`.

E.g. for PyPI vulnerabilities:

```bash
# Or download over HTTP via https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
gsutil cp gs://osv-vulnerabilities/PyPI/all.zip .
```

A list of all current ecosystems is available at 
[`gs://osv-vulnerabilities/ecosystems.txt`](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)
