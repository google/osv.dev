---
layout: page
title: FAQ
permalink: /faq/
nav_order: 4
---

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Background

### What is OSV?

OSV consists of:

1. [The OSV Schema](https://ossf.github.io/osv-schema/): An easy-to-use data
   format that maps precisely to open source versioning schemes.
2. Reference infrastructure ([OSV.dev website](https://osv.dev/),
   [API](../api/), and tooling) that aggregates,
   [enriches](#what-does-osvdev-do-to-the-records-it-imports) and indexes
   vulnerability data from databases that use the OSV schema.
3. [OSV-Scanner](https://github.com/google/osv-scanner), the officially
   supported frontend for OSV.dev

We created OSV to address many of the shortcomings of dealing with vulnerabilities in open source software using existing solutions.

See our blog posts for more details:

1. [Launching OSV](https://security.googleblog.com/2021/02/launching-osv-better-vulnerability.html)
2. [Announcing a unified vulnerability schema for open source](https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html)
3. [OSV and the Vulnerability Life Cycle](https://security.googleblog.com/2023/03/osv-and-vulnerability-life-cycle.html)

### Who is OSV for?

The OSV schema and OSV.dev can be used by:

1. Open source consumers: By querying [OSV.dev's API](../api/) and using our tooling to find known vulnerabilities in their dependencies.
2. Open source projects: By publishing vulnerabilities in the OSV format and having them imported by OSV.dev.
3. Vulnerability database producers: By making the database available in the OSV format.

### Why a new format to describe vulnerability?

We found that there was no existing standard format which:

1. Enforces version specification that precisely matches naming and versioning schemes used in actual open source package ecosystems. For instance, matching a vulnerability such as a CVE to a package name and set of versions in a package manager is difficult to do in an automated way using existing mechanisms such as CPEs.
2. Can be used to describe vulnerabilities in any open source ecosystem, while not requiring ecosystem-dependent logic to process them.
3. Is easy to use by both automated systems and humans.

A unified format means that vulnerability databases, open source users, and security researchers can easily share tooling and consume vulnerabilities across all of open source. This means a more complete view of vulnerabilities in open source for everyone, as well as faster detection and remediation times resulting from easier automation.

### Who is using the OSV schema?

The benefits of the OSV schema have led to adoption by several vulnerability databases, including GitHub Security Advisories, PyPA, RustSec, and many more. The full list of databases can be found [here](https://github.com/ossf/osv-schema#open-source-vulnerability-schema).

## Usage

### How do I use OSV as an open source user?

OSV.dev provides an [easy-to-use API](../api/) for querying against the aggregated database of vulnerabilities.

[Command line tooling](https://github.com/google/osv-scanner) is also available for vulnerability scanning of SBOMs, language manifests, and container images.

There are numerous third-party integrations with the API, and we have stopped maintaining an exhaustive list. You can try [this GitHub search](https://github.com/search?q=%22api.osv.dev%22&type=code) as a starting point.

### How do I use OSV as a vulnerability database maintainer?

By [making your vulnerability database available in the OSV format](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md#contributing-data), open source users will have a consistent way to consume vulnerabilities across all open source ecosystems.

Vulnerability databases can also benefit from easier interchange and vulnerability sharing from other databases that use the OSV format.

### How do I contribute to OSV, or ask a question?

OSV is completely open source!

1. The infrastructure code is available [here](https://github.com/google/osv.dev)
2. OSV-Scanner code is available [here](https://github.com/google/osv-scanner)
3. The OSV schema spec is available [here](https://github.com/ossf/osv-schema)

If you have any questions, please feel free to create an issue!

## Data

### I've found something wrong with the data

Data quality is very important to us. Please remember that OSV.dev is an
aggregator of OSV records from a [variety of
sources](https://github.com/google/osv.dev/blob/master/source.yaml) and the most
appropriate place to correct the data is at the source.

We prefer to avoid needing to act as a broker between downstream consumers of
the data and upstream sources, as this adds limited value, and only adds delays.

Where available, a human-friendly link to the authoritative record source is
available as the `Source` field on the individual vulnerability page. You should
follow the source-specific process for updating the data.

For sources that are a Git repository, the `Import Source` field points to the
authoritative source of the data, and you may be able to create a pull/merge
request or file an issue against the repository.

If you are not able to get satisfaction after dealing directly with the source of the data, please [file an issue](https://github.com/google/osv.dev/issues?q=is%3Aissue+is%3Aopen+label%3A%22data+quality%22) tagged with `data quality`.

### Is the database available to download?

Yes!

The database in available in a GCS bucket maintained by OSV: [gs://osv-vulnerabilities](https://storage.googleapis.com/osv-vulnerabilities/index.html) (also [publicly browseable via the Google Cloud Console](https://console.cloud.google.com/storage/browser/osv-vulnerabilities) with a login)

More information about how to download the database is available [here](data.md#data-dumps).

### Can I contribute data?

Yes!

If you work on a project (like a Linux distribution) and would like to contribute security advisories, please see our data contribution [guide](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md#contributing-data) on GitHub.

### What does OSV.dev do to the records it imports?

1. Version enumeration (for non-SemVer ecosystems where [supporting version enumeration code](https://github.com/google/osv.dev/tree/master/osv/ecosystems) exists)
2. [Package URL](https://github.com/package-url/purl-spec) [computation](https://github.com/google/osv.dev/blob/a751ceb26522f093edf26c0ad167cfd0967716d9/osv/models.py#L361-L365) (if necessary)
3. [Git affected commit enumeration and commit to tag mapping](https://github.com/google/osv.dev/blob/a751ceb26522f093edf26c0ad167cfd0967716d9/osv/impact.py#L422)
4. [Batch](https://github.com/google/osv.dev/blob/master/deployment/clouddeploy/gke-workers/base/alias-computation.yaml) [computation](https://github.com/google/osv.dev/tree/master/docker/alias) of [aliases](https://ossf.github.io/osv-schema/#aliases-field)

Both version and commit enumeration populate the [`affected.versions[]`](https://ossf.github.io/osv-schema/#affectedversions-field) field, which assists with precise version matching.

In some cases, there may be no applicable versions, so the `affected.versions[]`
array is empty. This field, when empty, is omitted in the API output, and
present (but empty) in the [data exports](#is-the-database-available-to-download).

### How does OSV.dev handle withdrawn records?

Records that have the [`withdrawn`](https://ossf.github.io/osv-schema/#withdrawn-field) field set will be excluded from:

* the responses to POST API queries
* the main [list page](https://osv.dev/list) and related search results

The entry remains in the database, and is:

* returned by the `/vulns/<ID>` GET API
* visible at `https://osv.dev/vulnerability/<ID>` page (and clearly visibly marked as "withdrawn")
* still exported in the [GCS exports](#is-the-database-available-to-download) (including the `withdrawn` field)

### How does OSV.dev handle deleted records?

When a record is deleted from an upstream source, OSV.dev currently handles them differently, depending on where they're imported from:

* GCS sources: OSV.dev marks deleted records as [`withdrawn`](https://ossf.github.io/osv-schema/#withdrawn-field). There is additionally a safety threshold in the case of feed availability issues: if more than 10% of records are about to be marked as `withdrawn`, OSV.dev aborts and does not proceed.
* REST and Git sources: OSV.dev leaves the existing records valid but orphaned. This behaviour will be changed to match the GCS source. See <https://github.com/google/osv.dev/issues/2101> and <https://github.com/google/osv.dev/issues/2294>.

## Infrastructure

### Is the API rate limited?

No. Currently there is not a limit on the API.

### What are OSV.dev's service level objectives (SLOs)?

OSV.dev strives to provide reliable vulnerability information to our users. To support that goal, the following service level objectives are targeted:

1. Availability, website and API: 99.9% measured on a 7 day rolling window.
2. Latency, website and API: P50 ≤ 300ms, P90 ≤ 500ms, P95 ≤ 1s, that is 50% of requests will be faster than 300ms, 90% of requests will be faster than 500ms, and 95% of requests will be faster than 1s.
3. Data Freshness: Data sources no more than 15 minutes stale, 99.5% of the time.
