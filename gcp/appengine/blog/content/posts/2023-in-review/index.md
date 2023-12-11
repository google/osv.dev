---
title: "The Year in Review"
date: 2023-12-11T04:00:00Z
draft: false
author: The OSV Team
---
2023 has been a *very* eventful year for OSV.

## New ecosystems support

[OSV Schema](https://github.com/ossf/osv-schema) adoption continues to grow! This year alone, 8 new ecosystems have adopted the schema, and are now included in our [OSV.dev](https://osv.dev/list) database:

* [AlmaLinux](https://osv.dev/blog/posts/almalinux-and-rocky-linux-join-osv/)
* [Bitnami](https://github.com/bitnami/vulndb)
* [Curl](https://curl.se/docs/vuln.json) (currently blocked on [#1235](https://github.com/google/osv.dev/issues/1235) for ingestion into OSV.dev)
* [Malicious Packages](https://openssf.org/blog/2023/10/12/introducing-openssfs-malicious-packages-repository/)
* [R](https://github.com/RConsortium/r-advisory-database)
* [Rocky Linux](https://osv.dev/blog/posts/almalinux-and-rocky-linux-join-osv/)
* [Haskell](https://github.com/haskell/security-advisories)
* [Python Software Foundation](https://discuss.python.org/t/the-python-software-foundation-has-been-authorized-by-the-cve-program-as-a-cve-numbering-authority-cna/32561/3)

This has brought the total number of supported ecosystems to 20. In particular, we have seen increased interest from Linux distributions, and expect to see further growth in adoption in 2024.

### C/C++

C and C++ dependencies remain a critical pillar of open source supply chains. We've expanded our C and C++ coverage by enriching our database with over [30,000 advisories](https://osv.dev/blog/posts/introducing-broad-c-c++-support/) with commit-level vulnerability information sourced from NVD's CVE records.

Our commit level vulnerability information paired with the [experimental determineversion API](https://osv.dev/blog/posts/using-the-determineversion-api/) enables OSV-Scanner to detect vulnerabilities in C and C++ dependencies used as submodules or directly vendored into source code. Our improvements in C and C++ support closes an important gap in vulnerability detection. 

## Infrastructure

Behind the scenes, we've optimized OSV.dev's API for performance and reliability, to ensure we maintain our [recently defined](https://osv.dev/blog/posts/announcing-osv-service-level-objectives/) [Service Level Objectives](https://google.github.io/osv.dev/faq/#what-are-osvs-service-level-objectives-slos).

We've also made changes to make our API easier to use, such as returning the transitive closure of [`aliases`](https://ossf.github.io/osv-schema/#aliases-field) to make it easier for users to deduplicate OSV entries across different databases.

We saw peaks in API usage of over 300 QPS in November.

![Image shows the GitHub star history for all OSV-related GitHub repositories taken at November 17, 2023. osv-schema has approximately 150 stars, osv.dev has approximately 1,300 stars, and osv-scanner has approximately 5,400 stars.](star-history-20231117.png "GitHub star history for all OSV repos, as of 2023/11/17")

## Community

There’s been a very pleasing uptick in both interest and external contributions
to both OSV.dev ([23 total contributors](https://github.com/google/osv.dev/graphs/contributors?from=2023-01-01&to=2023-12-31&type=c)) and OSV-Scanner ([32 total contributors](https://github.com/google/osv-scanner/graphs/contributors?from=2023-01-01&to=2023-12-31&type=c))

We also gave an [update on OSV at the OpenSSF Day Europe](https://www.youtube.com/watch?v=WvMXsm_BEf4), in Bilbao, Spain in September.

## Tooling
Since OSV-Scanner's launch [one year ago](https://security.googleblog.com/2022/12/announcing-osv-scanner-vulnerability.html), we've added
several significant new features. 

* [Reachability analysis](https://google.github.io/osv-scanner/experimental/#scanning-with-call-analysis) to reduce false positives
  * [Govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) integration to enable reachability analysis of Go vulnerabilities
  * [Experimental Rust call analysis](https://google.github.io/osv-scanner/usage/#call-analysis-in-rust) to enable reachability analysis of Rust vulnerabilities
* Comprehensive [C/C++ vulnerability management support](https://osv.dev/blog/posts/introducing-broad-c-c++-support/)
  * Git submodule scanning
  * [Vendored dependency detection](https://osv.dev/blog/posts/using-the-determineversion-api/)
* Improved ecosystem and scanning format support
  * Improved SBOM support
  * NuGet
  * ConanCenter
* An experimental [offline mode](https://google.github.io/osv-scanner/experimental/#offline-mode)
* An experimental [GitHub Action](https://google.github.io/osv-scanner/github-action/) (including SARIF output support)
* An experimental [license scanning feature](https://osv.dev/blog/posts/introducing-license-scanning-with-osv-scanner/)

## More to come in 2024

The team is looking forward to much more to come in 2024 and the OSV Schema and OSV.dev’s third birthday in February, and OSV-Scanner’s first birthday in December. 

We have a lot more exciting work planned in 2024, that we’ll share more details soon. Our main priorities for 2024 are centered around improving data quality and providing
accurate and actionable results that lead to easy remediation.

We will support these priorities in the following ways:

### 1. Building validation and feedback mechanisms for OSV sources to ensure high data quality
As OSV Schema adoption grows, it’s become even more important to ensure consistency and high data quality across all data sources. We plan to provide better validation tools, and build feedback channels to  make it easier for OSV data sources to ensure high quality of data.

### 2. Ensuring accurate and comprehensive scanning
A continuing focus for OSV-Scanner is making sure that our scanning is comprehensive and accurate. Accuracy is especially important for us, as one of our core goals is to minimize false positives and vulnerability noise for developers at the receiving end of the scanners.

### 3. Improving container scanning
OSV-Scanner has so far focused on source repository scanning. One important gap we aim to fill is to provide better support for container scanning, in a way that provides actionable and useful remediation guidance.

### 4. Releasing remediation tools 
Developers are often faced with an overwhelming number of vulnerabilities reported against their dependencies. We are currently building tooling to enable developers to both interactively and automatically prioritize and fix the vulnerabilities that matter in an easy way.

Here’s a [quick preview](https://github.com/google/osv-scanner/issues/352#issuecomment-1820008675) of what we have been working on: 

![A sneak preview of the current UX of the guided remediation tooling under development. The screenshot shows a number of options the user can take to remediate vulnerabilities.](guided_remediation1.png "A screenshot of the guided remediation tooling under development")
![A sneak preview of the current UX of the guided remediation tooling under development. This screen shot shows a summary of the vulnerabilities and a proposed action.](guided_remediation2.png "A screenshot of the guided remediation tooling under development")
