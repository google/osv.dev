---
layout: home
nav_order: 1
---
# Introduction to OSV

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv.dev/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv.dev)

OSV enables developers to identify known third-party open source dependency
vulnerabilities that pose genuine risk to their application and its environment,
so they can focus remediation efforts on the vulnerabilities that matter and
sustainably manage vulnerabilities that do not affect them.

[This repository](https://github.com/google/osv.dev) contains the infrastructure
code that serves [osv.dev](https://osv.dev) (including the
[API](https://google.github.io/osv.dev/api/)).  This infrastructure serves as an
aggregator of vulnerability databases that have adopted the [OpenSSF
Vulnerability format](https://github.com/ossf/osv-schema).

[osv.dev](https://osv.dev) additionally provides infrastructure to ensure
affected versions are accurately represented in each vulnerability entry,
through bisection and version analysis.

Further information on the infrastructure architecture is available
[here](contributing/architecture.md).

[OSV-Scanner](https://google.github.io/osv-scanner/), is the first-party tool
that leverages OSV.dev's data, using its API.

![This is a diagram that shows the relationship between the vulnerability
databases that use the OSV format and how all those entries are collated at
OSV.dev. Open source users can query for known vulnerabilities by version number
or commit hash.](images/diagram.png)
