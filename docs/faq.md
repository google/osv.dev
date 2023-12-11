---
layout: page
title: FAQ
permalink: /faq/
nav_order: 4
---
# FAQ
{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## What is OSV?

OSV consists of:

1. [The OSV Schema](https://ossf.github.io/osv-schema/): An easy-to-use data format that maps precisely to open source versioning schemes.
2. Reference infrastructure (this site, API, and tooling) that aggregates and indexes vulnerability data from databases that use the OSV schema.

We created OSV to address many of the shortcomings of dealing with vulnerabilities in open source software using existing solutions.

See our blog posts for more details:

1. [Launching OSV](https://security.googleblog.com/2021/02/launching-osv-better-vulnerability.html)
2. [Announcing a unified vulnerability schema for open source](https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html)
3. [OSV and the Vulnerability Life Cycle](https://security.googleblog.com/2023/03/osv-and-vulnerability-life-cycle.html)

## Who is OSV for?
OSV can be used by both:

1. Open source consumers: By querying our API and using our tooling to find known vulnerabilities in their dependencies.
2. Vulnerability database producers: By making the database available in the OSV format.

## Why a new format to describe vulnerability?

We found that there was no existing standard format which:

1. Enforces version specification that precisely matches naming and versioning schemes used in actual open source package ecosystems. For instance, matching a vulnerability such as a CVE to a package name and set of versions in a package manager is difficult to do in an automated way using existing mechanisms such as CPEs.
2. Can be used to describe vulnerabilities in any open source ecosystem, while not requiring ecosystem-dependent logic to process them.
3. Is easy to use by both automated systems and humans.

A unified format means that vulnerability databases, open source users, and security researchers can easily share tooling and consume vulnerabilities across all of open source. This means a more complete view of vulnerabilities in open source for everyone, as well as faster detection and remediation times resulting from easier automation.

## Who is using the OSV schema?

The benefits of the OSV schema have led to adoption by several vulnerability databases, including GitHub Security Advisories, PyPA, RustSec, and many more. The full list of databases can be found [here](https://github.com/ossf/osv-schema#open-source-vulnerability-schema).

## How do I use OSV as an open source user?
OSV provides an easy-to-use API for querying against the aggregated database of vulnerabilities.

[Command line tooling](https://github.com/google/osv-scanner) is also available for vulnerability scanning of SBOMs, language manifests, and container images.

## How do I use OSV as a vulnerability database maintainer?
By making your vulnerability database available in the OSV format, open source users will have a consistent way to consume vulnerabilities across all open source ecosystems.

Vulnerability databases can also benefit from easier interchange and vulnerability sharing from other databases that use the OSV format.

## Is the database available to download?
Yes!

The database in available in a GCS bucket maintained by OSV: [gs://osv-vulnerabilities](https://osv-vulnerabilities.storage.googleapis.com/) (also [publicly browseable via the Google Cloud Console](https://console.cloud.google.com/storage/browser/osv-vulnerabilities) with a login)

More information about how to download the database is available [here](data.md#data-dumps).

## What are OSV's service level objectives (SLOs)?
OSV strives to provide reliable vulnerability information to our users. To support that goal, target the following service level objectives:

1. Availability, website and API: 99.9% measured on a 7 day rolling window.
2. Latency, website and API: P50 ≤ 300ms, P90 ≤ 500ms, P95 ≤ 1s, that is 50% of requests will be faster than 300ms, 90% of requests will be faster than 500ms, and 95% of requests will be faster than 1s.
3. Data Freshness: Data sources no more than 15 minutes stale, 99.5% of the time.

## How do I contribute to OSV, or ask a question?
OSV is completely open source!

1. The infrastructure code is available [here](https://github.com/google/osv.dev)
2. OSV-Scanner code is available [here](https://github.com/google/osv-scanner)
3. The OSV schema spec is available [here](https://github.com/ossf/osv-schema)

If you have any questions, please feel free to create an issue!

## Can I contribute data?
Yes!

If you work on a project (like a Linux distribution) and would like to contribute security advisories, please see our data contribution [guide](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md#contributing-data) on GitHub.

## Is the API rate limited?
No. Currently there is not a limit on the API. 
