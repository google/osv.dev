---
title: "API Queries for More Linux Distributions"
date: 2024-10-22T00:00:00Z
draft: false
author: Holly Gong
---

We're excited to announce that OSV.dev's API now allows you to query all our supported Linux distributions!

2024 has seen significant adoption of the OSV Schema from prominent Linux distributions such as [Ubuntu](https://openssf.org/blog/2024/06/11/ubuntu-security-notices-now-available-in-osv/), [Chainguard/Wolfi](https://openssf.org/blog/2024/07/03/chainguard-enhances-security-with-osv-advisory-feed/), and [SUSE/openSUSE](https://www.suse.com/support/update/). In particular, Ubuntu provides us with both [Ubuntu Security Notices](https://ubuntu.com/security/notices) (identified as `USN-`) and [Ubuntu CVE Tracker](https://ubuntu.com/security/cves) (identified as `UBUNTU-CVE-`) to cover fixed and unfixed vulnerabilities. Chainguard/Wolfi and SUSE/openSUSE have also recently adopted the OSV Schema. This increased community adoption allows us to expand our Linux distribution vulnerability coverage significantly.

Although we had expanded our coverage of Linux distributions, we didn't support API queries for many of them due to limitations in our query implementation. Specifically, the OSV.dev API relied solely on enumerated affected versions for package version queries, requiring version enumeration functions to be implemented for each ecosystem. This approach was difficult to scale and limited our API queries to only Debian, Ubuntu, and Alpine, and was a barrier to utilizing the data already available.

To overcome the limitations of our previous implementation, we developed a new [affected range matching method](https://github.com/google/osv.dev/issues/2401). This new method eliminates the need for version enumeration, allowing us to support queries for a wider range of Linux distributions. As a result, OSV.dev now supports package version queries across all our Linux distributions, including Rocky Linux, AlmaLinux, Chainguard/Wolfi, and SUSE/openSUSE. Furthermore, with this new method, any new Linux distribution that publishes vulnerabilities in the OSV Schema and is imported by OSV.dev in the future will be queryable.

```bash
curl -d \
'{"package": {"name": "nodejs", "ecosystem": "AlmaLinux"},
"version": "1:16.13.1-3.module_el8.5.0+2605+45d748af"}' \
https://api.osv.dev/v1/query
```

This year, the OSV team has had a big focus on container image scanning. With the improved Linux distribution data and API query capabilities, we will deliver even better results for container image scanning. In our next OSV container image scanning update, we'll dive deeper into base image identification and layer attribution. Additionally, we'll unveil a new output format for OSV-Scanner. Stay tuned for more!
