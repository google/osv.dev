---
layout: home
nav_order: 1
---
# Introduction to OSV

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv.dev/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv.dev)

OSV seeks to reduce the complexities of open-source software security
vulnerability management with the data in the [OSV
schema](https://ossf.github.io/osv-schema/), aggregated in the database
available at [OSV.dev](https://osv.dev/list), available via its
[API](/osv.dev/api/), and related tooling like
[OSV-Scanner](https://google.github.io/osv-scanner/), that leverages it.

[This repository](https://github.com/google/osv.dev) contains the infrastructure
code that serves [osv.dev](https://osv.dev) (and other user tooling). This
infrastructure serves as an aggregator of vulnerability databases that have
adopted the [OpenSSF Vulnerability format](https://github.com/ossf/osv-schema).

[osv.dev](https://osv.dev) additionally provides infrastructure to ensure
affected versions are accurately represented in each vulnerability entry,
through bisection and version analysis.

Further information on the infrastructure architecture is available
[here](contributing/architecture.md).

![This is a diagram that shows the relationship between the vulnerability
databases that use the OSV format and how all those entries are collated at
OSV.dev. Open source users can query for known vulnerabilities by version number
or commit hash.](images/diagram.png)
