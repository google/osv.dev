[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv.dev/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv.dev)

# OSV - Open Source Vulnerabilities

[osv.dev] is a [vulnerability database] and triage infrastructure for open
source projects aimed at helping both open source maintainers and consumers of
open source.

This repository contains the infrastructure code that serves
[osv.dev](and other user tooling). This infrastructure serves as an aggregator
of vulnerability databases that have adopted the
[OpenSSF Vulnerability format](https://github.com/ossf/osv-schema).

[osv.dev] additionally provides infrastructure to ensure affected versions are
accurately represented in each vulnerability entry, through bisection and
version analysis.

[osv.dev]: https://osv.dev
[vulnerability database]: https://osv.dev/list

<p align="center">
  <img src="docs/images/diagram.png" width="600">
</p>

## Current data sources

**This is an ongoing project.** We encourage open source ecosystems to adopt the
[OpenSSF Vulnerability format](https://ossf.github.io/osv-schema/) to enable
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

Additionally, the OSV.dev team maintains a conversion pipeline for:

-   [Debian Security Advisories](https://storage.googleapis.com/debian-osv/index.html),
    using the conversion tools
    [here](https://github.com/ossf/osv-schema/tree/main/tools/debian).
-   [Alpine SecDB](https://storage.googleapis.com/cve-osv-conversion/index.html?prefix=osv-output/),
    using the conversion tools
    [here](https://github.com/google/osv.dev/tree/master/vulnfeeds/cmd/alpine).

Together, these include vulnerabilities from:

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
-   RubyGems

### Data dumps

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
[`gs://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt`](https://osv-vulnerabilities.storage.googleapis.com/ecosystems.txt)

## Viewing the web UI

An instance of OSV's web UI is deployed at <https://osv.dev>.

## Using the API

```bash
  curl -d \
      '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
      "https://api.osv.dev/v1/query"

  curl -d \
      '{"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
      "https://api.osv.dev/v1/query"
```

Detailed documentation for using the API can be found at
<https://osv.dev/docs/>.

## Using the scanner

We provide a Go based tool that will scan your dependencies, and check them
against the OSV database for known vulnerabilities via the OSV API.

Currently it is able to scan various lockfiles, debian docker containers, SPDX
and CycloneDB SBOMs, and git repositories.

The scanner is located in it's
[own repository here](https://github.com/google/osv-scanner).

## Architecture

You can find an overview of OSV's architecture [here](docs/architecture.md).

## This repository

This repository contains all the code for running https://osv.dev on GCP. This
consists of:

-   API server (`gcp/api`)
-   Web interface (`gcp/appengine`)
-   Workers for bisection and impact analysis (`docker/worker`)

You'll need to check out submodules as well for many local building steps to
work:

```bash
git submodule update --init --recursive
```

## Contributing

Contributions are welcome! 

Learn more about [code](CONTRIBUTING.md#contributing-code) and [data](CONTRIBUTING.md#contributing-data) contributions. 
We also have a [mailing list](https://groups.google.com/g/osv-discuss) and an [FAQ](https://osv.dev/about). 

Do you have a question or a suggestion? Please [open an issue](https://github.com/google/osv.dev/issues). 

## Third party tools and integrations

There are also community tools that use OSV. Note that these are community built
tools and unsupported by the core OSV maintainers.

-   [Betterscan.io: Code Scanning/SAST/Static Analysis/Linting using many
    tools/Scanners with One Report (Code,
    IaC)](https://github.com/marcinguy/betterscan-ce)
-   [bomber](https://github.com/devops-kung-fu/bomber)
-   [Cortex XSOAR](https://github.com/demisto/content)
-   [Dependency-Track](https://github.com/DependencyTrack/dependency-track)
-   [dep-scan](https://github.com/AppThreat/dep-scan)
-   [EZE-CLI: The one stop shop for security testing in modern development](https://github.com/RiverSafeUK/eze-cli)
-   [Golang support for the schema](https://pkg.go.dev/golang.org/x/vuln/osv)
-   [G-Rath/osv-detector](https://github.com/G-Rath/osv-detector): A scanner
    that uses the OSV database.
-   [it-depends](https://github.com/trailofbits/it-depends)
-   [.NET client library and support for the schema](https://github.com/JamieMagee/osv.net)
-   [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort)
-   [Packj](https://github.com/ossillate-inc/packj)
-   [pip-audit](https://pypi.org/project/pip-audit/)
-   [Renovate](https://github.com/renovatebot/renovate)
-   [Rust client library](https://github.com/gcmurphy/osv)
-   [Skjold: Security audit python project dependencies against several security
    advisory databases](https://github.com/twu/skjold)
-   [Trivy](https://github.com/aquasecurity/trivy)

Feel free to send a PR to add your project here.
