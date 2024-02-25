[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv.dev/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv.dev)

## Documentation

Comprehensive documentation is available [here](https://google.github.io/osv.dev).
API documentation is available [here](https://google.github.io/osv.dev/api/).

## Viewing the web UI

An instance of OSV's web UI is deployed at <https://osv.dev>.

## Using the scanner

We provide a Go based tool that will scan your dependencies, and check them against the OSV database for known vulnerabilities via the OSV API.

Currently it is able to scan various lockfiles, debian docker containers, SPDX and CycloneDB SBOMs, and git repositories.

The scanner is located in its [own repository](https://github.com/google/osv-scanner).

## This repository

This repository contains all the code for running https://osv.dev on GCP. This
consists of:

| directory       | what |
|-----------------|------|
| `deployment/`   | Terraform, Cloud Deploy & App Engine config files <br /> A few Cloud Build config yamls <br /> Old (no longer used?) `api-staging` and `api-test` Cloud Run configs  |
| `docker/`       | CI docker files (`ci`, `deployment`, `terraform`) <br /> Workers for bisection and impact analysis (`worker`, `importer`, `exporter`, `alias`, `worker-base`) <br /> The determine version `indexer`<br /> `cron/` jobs for database backups and processing oss-fuzz records |
| `docs/`         | Jekyll files for https://google.github.io/osv.dev/ <br /> `build_swagger.py` and `tools.go` |
| `gcp/api`       | OSV API server files (including files for the local ESP server) <br /> protobuf files in `/v1`|
| `gcp/appengine` | The backend of the osv.dev web interface, with the frontend in `frontend3` <br /> Blog posts (in `blog`) <br /> App Engine Cron Handlers (to be removed) <br /> The  datastore indexes file (`index.yaml`) | 
| `gcp/functions` | The Cloud Function for publishing PyPI vulnerabilities (maintained, but not developed) |
| `osv/`          | The core OSV Python library, used in basically all Python services <br /> OSV ecosystem package versioning helpers in `ecosystems/` <br /> Datastore model definitions in `models.py` |
| `tools/`        | Misc scripts/tools, mostly intended for development (datastore stuff, linting) <br /> The `indexer-api-caller` for indexer calling |
| `vulnfeeds/`    | Go module for (mostly) the NVD CVE conversion <br /> The Alpine feed converter (`cmd/alpine`) <br /> The Debian feed converter (`tools/debian`, which is written in Python) |


You'll need to check out submodules as well for many local building steps to
work:

```bash
git submodule update --init --recursive
```

## Contributing

Contributions are welcome! 

Learn more about [code](CONTRIBUTING.md#contributing-code), [data](CONTRIBUTING.md#contributing-data), and [documentation](CONTRIBUTING.md#contributing-documentation) contributions. 
We also have a [mailing list](https://groups.google.com/g/osv-discuss). 

Do you have a question or a suggestion? Please [open an issue](https://github.com/google/osv.dev/issues). 

## Third party tools and integrations

There are also community tools that use OSV. Note that these are community built
tools and unsupported by the core OSV maintainers.

-   [Betterscan.io: Code Scanning/SAST/Static Analysis/Linting using many
    tools/Scanners with One Report (Code,
    IaC)](https://github.com/marcinguy/betterscan-ce)
-   [bomber](https://github.com/devops-kung-fu/bomber)
-   [Cortex XSOAR](https://github.com/demisto/content)
-   [dependency-management-data](https://dmd.tanna.dev)
-   [Dependency-Track](https://github.com/DependencyTrack/dependency-track)
-   [dep-scan](https://github.com/AppThreat/dep-scan)
-   [EZE-CLI: The one stop shop for security testing in modern development](https://github.com/RiverSafeUK/eze-cli)
-   [G-Rath/osv-detector](https://github.com/G-Rath/osv-detector): A scanner
    that uses the OSV database.
-   [GUAC](https://guac.sh)
-   [it-depends](https://github.com/trailofbits/it-depends)
-   [.NET client library and support for the schema](https://github.com/JamieMagee/osv.net)
-   [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort)
-   [OSV4k: a Java/Kotlin MPP library for serialization and deserialization of OSV schema](https://github.com/saveourtool/osv4k)
-   [Packj](https://github.com/ossillate-inc/packj)
-   [pip-audit](https://pypi.org/project/pip-audit/)
-   [Renovate](https://github.com/renovatebot/renovate)
-   [rosv: an R package to access the OSV database and help administer Posit Package Manager](https://github.com/al-obrien/rosv)
-   [Rust client library](https://github.com/gcmurphy/osv)
-   [Skjold: Security audit python project dependencies against several security
    advisory databases](https://github.com/twu/skjold)
-   [Trivy](https://github.com/aquasecurity/trivy)
-   [IronDome](https://rubygems.org/gems/iron_dome)

Feel free to send a PR to add your project here.
