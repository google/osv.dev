---
title: "The Year in Review"
date: 2024-12-13T04:00:00Z
draft: false
author: The OSV Team
---
2024 has been an *even more* eventful year for OSV.

<!--more-->

## New ecosystems support

[OSV Schema](https://github.com/ossf/osv-schema) adoption momentum continued, with 2024 being the year of the Linux distributions with four adopting the schema, and now included in our [OSV.dev](https://osv.dev/list) database:

* [Ubuntu](https://openssf.org/blog/2024/06/11/ubuntu-security-notices-now-available-in-osv/)
* [Chainguard](https://openssf.org/blog/2024/07/03/chainguard-enhances-security-with-osv-advisory-feed/)
* [Red Hat](https://openssf.org/blog/2024/11/01/red-hats-collaboration-with-the-openssf-and-osv-dev-yields-results-red-hat-security-data-now-available-in-the-osv-format/)
* [SUSE/openSUSE](https://github.com/ossf/osv-schema/pull/260)

We also expanded our existing coverage of Debian GNU/Linux, by [including CVE data from their Security Tracker](https://osv.dev/blog/posts/supporting-debian-security-tracker-data/) in our existing CVE record conversion.

Additionally, the [curl project](https://curl.se/) [started contributing vulnerability records](https://osv.dev/blog/posts/announcing-curl-via-rest/).

This has brought the total number of supported ecosystems to 30. The significantly increased coverage of Linux distributions has been very encouraging, and will enable a comprehensive container image scanning story in 2025.

### Impact of the NVD's analysis challenges on Git commit range coverage

Last year, we [announced](https://osv.dev/blog/posts/introducing-broad-c-c++-support/) the expansion of coverage of C/C++ software with Git range coverage of CVEs
programmatically converted from the NVD. The [reduction of the NVD's analysis capabilities](https://www.scworld.com/news/update-delays-to-nist-vulnerability-database-alarms-researchers) has had a broad impact on vulnerability management, and it has also impacted the effectiveness and comprehensiveness of this CVE conversion. Even with this unexpected challenge, slightly over 50% of in-scope CVEs have been able to be converted to OSV records with the [current implementation](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/nvd-cve-osv).

On the expectation that this may persist into 2025, and in light of [related](https://github.com/cisagov/vulnrichment) [developments](https://www.cisa.gov/securebydesign/pledge) this year, we will be exploring additionally converting CVEs directly from the [CVE List](https://github.com/CVEProject/cvelist).

## Data Quality

We announced our [approach to data quality](https://osv.dev/blog/posts/announcing-data-quality-initiatives/), publishing a definition of the [Properties of a High Quality OSV Record](https://google.github.io/osv.dev/data_quality.html), and work on [this project](https://github.com/orgs/google/projects/62) is ongoing into 2025.

## Infrastructure

We added [support for importing records published at a REST API endpoint](https://osv.dev/blog/posts/announcing-curl-via-rest/), (with the [curl project](https://curl.se/) being the pilot home database to do so).

We also made improvements to the record import and ingestion processes, to be more tolerant of records with `GIT` ranges that are semantically valid, but incorrect, enabling more existing converted CVEs to be partially imported successfully.

A very impactful change to the OSV.dev [API](https://google.github.io/osv.dev/api/) has been the [ability to perform queries on existing and future data that OSV.dev did not have version enumeration support for](https://osv.dev/blog/posts/announcing-api-queries-for-more-linux-distros/). This unlocked the usage of existing data for vulnerability discovery via the API, and reduces the effort required to onboard additional ecosystems into the future.

We also continued to make performance and reliability improvements to the API, and transitioned the website serving infrastructure from Google App Engine to Cloud Run.

OSV.dev API usage of peaked at over 900 QPS in October.

With the growth in ecosystems, we took the opportunity to [simplify the exported data](https://groups.google.com/g/osv-discuss/c/V7ZSZEMewGA) in our public GCS bucket.

## Community

### Code

![Image shows the GitHub star history for all OSV-related GitHub repositories taken at November 27, 2024. osv-schema has approximately 180 stars, osv.dev has approximately 1,500 stars, osv-scanner has approximately 6,270 stars, and osv-scanner-action has 16 stars.](star-history-20241127.png "GitHub star history for all OSV repos, as of 2024/11/27")

Interest and external contributions continue:

* OSV Schema
  * [18 total contributors](https://github.com/ossf/osv-schema/graphs/contributors?from=2024-01-01&to=2024-12-31&type=c)
* OSV.dev
  * [28 total contributors](https://github.com/google/osv.dev/graphs/contributors?from=2024-01-01&to=2024-12-31&type=c)
* OSV-Scanner
  * [32 total contributors](https://github.com/google/osv-scanner/graphs/contributors?from=2024-01-01&to=2024-12-31&type=c)
* OSV-Scanner GitHub Action
  * [8 total contributors](https://github.com/google/osv-scanner-action/graphs/contributors?from=2024-01-01&to=2024-12-31&type=c)
  * Over 400 GitHub repositories have [adopted](https://github.com/google/osv-scanner-action/network/dependents)

### Conferences and events

We gave OSV-related presentations at:

* [The inaugural VulnCon](https://www.first.org/conference/vulncon2024/program#pThe-Trials-and-Tribulations-of-Bulk-Converting-CVEs-to-OSV) in Raleigh, North Carolina, USA in February
* [The SOSS Community Day](https://sosscdna24.sched.com/event/1aNLy/beyond-just-update-all-the-things-uncovering-the-nuances-of-dependency-security-rex-pan-holly-gong-google) in Seattle, Washington, USA in April
* [The Open Source Summit, Japan](https://ossaidevjapan24.sched.com/event/1jKDY/trials-and-tribulations-of-updating-dependencies-for-vulnerability-remediation-xueqin-cui-michael-kedar-google) in Tokyo, Japan in October

## Tooling

### OSV-Scanner

This year, OSV-Scanner gained these noteworthy new features:

* [Guided Remediation](https://osv.dev/blog/posts/announcing-guided-remediation-in-osv-scanner/) for npm
* [Transitive dependency scanning for Maven](https://osv.dev/blog/posts/announcing-transitive-dependency-support-for-maven-pomxml-in-osv-scanner/)
* Support for private Maven registries
* The ability to override findings in specific packages
* Additional support for scanning
  * NuGet version 2 lock files
  * pdm lockfiles
  * PNPM v9 lockfiles
  * gradle/verification-metadata.xml
  * CycloneDX 1.4 and 1.5

### A linter for OSV records

As part of the our data quality program, work commencing on an [OSV record linting tool](https://github.com/ossf/osv-schema/tree/main/tools/osv-linter), which will carry on into 2025.

## More to come in 2025

The team is looking forward to much more to come in 2025 and the OSV Schema and OSV.dev’s fourth birthday in February, and OSV-Scanner’s second birthday in December.

We have a lot more exciting work planned in 2025, that we’ll share more details soon. Our main priorities for 2025 continue to be centered around improving data
quality and providing accurate and actionable results that lead to easy remediation.
