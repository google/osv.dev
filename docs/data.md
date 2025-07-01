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
-   [Rocky Linux](https://distro-tools.rocky.page/apollo/openapi/#osv)
    ([BSD](https://rockylinux.org/licensing))
-   [AlmaLinux](https://github.com/AlmaLinux/osv-database)
    ([MIT](https://github.com/AlmaLinux/osv-database/blob/master/LICENSE))
-   [Haskell Security Advisories](https://github.com/haskell/security-advisories)
    ([CC0 1.0](https://github.com/haskell/security-advisories/blob/main/LICENSE.txt))
-   [RConsortium Advisory Database](https://github.com/RConsortium/r-advisory-database)
    ([Apache 2.0](https://github.com/RConsortium/r-advisory-database/blob/main/LICENSE))
-   [OpenSSF Malicious Packages](https://github.com/ossf/malicious-packages)
    ([Apache 2.0](https://github.com/ossf/malicious-packages/blob/main/LICENSE))
-   [Python Software Foundation Database](https://github.com/psf/advisory-database)
    ([CC-BY 4.0](https://github.com/psf/advisory-database/blob/main/LICENSE))
-   [Bitnami Vulnerability Database](https://github.com/bitnami/vulndb)
    ([Apache 2.0](https://github.com/bitnami/vulndb/blob/main/LICENSE.md))
-   [Haskell Security Advisory DB](https://github.com/haskell/security-advisories)
    ([CC0 1.0](https://github.com/haskell/security-advisories/blob/main/LICENSE.txt))
-   [Ubuntu](https://github.com/canonical/ubuntu-security-notices)
    ([GPL v3](https://github.com/canonical/ubuntu-security-notices/blob/main/LICENSE))

## Converted data

Additionally, the OSV.dev team maintains a conversion pipeline for:

-   [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html),
    using the conversion tools
    [here](https://github.com/google/osv.dev/tree/master/vulnfeeds/tools/debian).
-   [Alpine SecDB](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/),
    using the conversion tools
    [here](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/alpine),
-   [NVD CVEs for open source software](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/) using the conversion tools [here](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/nvd-cve-osv)

## Covered Ecosystems

Between the data served in OSV and the data converted to OSV the following ecosystems are covered.

-   AlmaLinux
-   Alpine
-   Android
-   Bitnami
-   crates.io
-   Curl
-   Debian GNU/Linux
-   Git ([including C/C++](https://osv.dev/blog/posts/introducing-broad-c-c++-support/))
-   GitHub Actions
-   Go
-   Haskell
-   Hex
-   Linux kernel
-   Maven
-   npm
-   NuGet
-   OSS-Fuzz
-   Packagist
-   Pub
-   PyPI
-   Python
-   R (CRAN and Bioconductor)
-   Rocky Linux
-   RubyGems
-   SwiftURL
-   Ubuntu OS

## Data Quality

The quality of the data in OSV.dev [is very important to us](https://google.github.io/osv.dev/faq/#ive-found-something-wrong-with-the-data). The minimum quality bar for OSV records acceptable for import is documented [here](data_quality.md)

## Data dumps

For convenience, these sources are aggregated and [continuously](https://github.com/google/osv.dev/blob/master/deployment/clouddeploy/gke-workers/base/exporter.yaml) 
exported to a GCS bucket maintained by OSV:
[`gs://osv-vulnerabilities`](https://storage.googleapis.com/osv-vulnerabilities/index.html)

This bucket contains a zip file with all vulnerabilities across all ecosystems (including withdrawn records) at `gs://osv-vulnerabilities/all.zip`. This is the easiest way to download the entire OSV database.

Individual vulnerability records can be found at `gs://osv-vulnerabilities/<ECOSYSTEM>/<ID>.json`. A zip containing all vulnerabilities for each ecosystem is available at `gs://osv-vulnerabilities/<ECOSYSTEM>/all.zip`. Vulnerabilities without an ecosystem (typically withdrawn ones) are exported to the `gs://osv-vulnerabilities/[EMPTY]/` directory.

E.g. for PyPI vulnerabilities:

```bash
# Or download over HTTP via https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip
gsutil cp gs://osv-vulnerabilities/PyPI/all.zip .
```

Some ecosystems contain a `:` separator in the name (e.g. `Alpine:v3.17`). For these ecosystems, the data dump will always contain an ecosystem directory without the `:.*` suffix (e.g. `Alpine`). This will contain all the advisories of the ecosystem with the same prefix (e.g. All `Alpine:.*`).

A list of all current ecosystems is available at
[`gs://osv-vulnerabilities/ecosystems.txt`](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)

**Note:**
OSV.dev has stopped exporting entries for ecosystems with prefixes (e.g. All `Alpine:.*`). Please refer only to the main ecosystem, the one without the `:.*` suffix, for all vulnerabilities of that ecosystem.

## Contributing Data
If you work with a project such as a Linux distribution and would like to contribute your security advisories, please follow the steps outlined in the [New Data Source](./new_source.md) page.

Data can be supplied either through a public Git repository, to [REST API endpoints](./rest-api.md), or through a public GCS bucket.
