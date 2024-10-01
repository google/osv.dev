---
title: "OSV's approach to data quality"
date: 2024-09-30T09:00:00Z
draft: false
author: Andrew Pollock and Charl de Nysschen
---
OSV's mission is to enable developers to reduce security risk arising from known
vulnerabilities in open source components they use.

Part of the strategy to accomplish that mission is to provide a comprehensive,
accurate and timely database of known vulnerabilities covering both language
ecosystems and OS package distributions.

Today, OSV.dev's coverage is fast approaching 30 ecosystems, while also
importing records from almost as many disparate "[home databases](https://ossf.github.io/osv-schema/#id-modified-fields)".
As this number of federated data sources continues to grow, so does the prospect
of OSV records being expressed in ways that are detrimental to them being
effectively utilized in aggregate.

To ensure the accuracy and usability of OSV.dev's data at scale we have
initiated a program of work to prevent future regression in data quality as the
ecosystem of data contributions continues to grow.
<!--more-->

In our
[experiences](https://www.first.org/conference/vulncon2024/program#pThe-Trials-and-Tribulations-of-Bulk-Converting-CVEs-to-OSV)
from [interacting with the CVE Program and broader
ecosystem](https://osv.dev/blog/posts/introducing-broad-c-c++-support/), we've
found that the term "data quality" means different things to different people.

For OSV.dev, the primary objective is to enable awareness and remediation of
known vulnerabilities in open source components. To this end, "data quality"
means being able to reason about and act upon vulnerability records at scale.
This is why the OSV format was designed to enable machine-readability as its
primary use case. In order to programmatically reason about OSV records at
scale, a degree of consistent use of fields beyond what can be validated using
JSON Schema validation alone is necessary.

Problems that the OSV Data Quality Program seeks to address include:

- No way for record providers to know there are problems with records they have already
published
- OSV.dev accepts non-schema-compliant records OSV.dev accepts records
with other validity issues (such as invalid package names or non-existent
package versions)
- No turnkey way for an OSV record provider to bring the data
quality problem forward, to earlier in the record publication lifecycle
- No best practice tooling for OSV records to be created by a new OSV record provider
- [Downstream data consumers often mistake OSV.dev as the originator for the data
and provide feedback about it to us, rather than the record's originator](https://google.github.io/osv.dev/faq/#ive-found-something-wrong-with-the-data)
- Git repository owners may not be following best-practice release processes (such as
not using tags, or by using unusual tag naming conventions), confounding
OSV.dev's ability to resolve fix commits for fix versions, which isn't known
until the first time a vulnerability referencing the repository is published

We have published our current opinion on the [Properties of a High Quality OSV
Record](https://google.github.io/osv.dev/data_quality.html), which goes above
and beyond JSON Schema compliance, and are working on an open source [OSV record
linting tool](https://github.com/ossf/osv-schema/tree/main/tools/osv-linter) to
programmatically validate records against these properties.

Thereafter, we will begin gating record imports to records that meet the quality
requirements.

In order for the operators of home databases that OSV.dev imports from to be
able to reason about the acceptability of records published, they will be able
to:

- run the OSV linter against their records as part of their publication
workflow
- review OSV.dev's import findings about their records

You can follow our [progress on this journey on
GitHub](https://github.com/orgs/google/projects/62). Input and contributions
are, as always, appreciated.

If you're responsible for an existing home database that OSV.dev imports records
from, we will contact you directly before there are any changes to the record
import process that may impact you. You can also consider proactively running
our OSV record linter on your existing records to see how they rate.

If you'd like to experiment with or help expand the capabilities of the OSV
record linter, it's [currently residing in the OpenSSF OSV Schema GitHub
repository](https://github.com/ossf/osv-schema/tree/main/tools/osv-linter).

As an end-consumer of OSV.dev's data, we hope that this blog post encourages you
to continue to have confidence in the capabilities enabled by that data into the
future.
