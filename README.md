[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv.dev/badge)](https://scorecard.dev/viewer/?uri=github.com/google/osv.dev)

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
| `deployment/`   | Terraform & Cloud Deploy config files <br /> A few Cloud Build config yamls |
| `docker/`       | CI docker files (`ci`, `deployment`, `terraform`) <br /> Workers for bisection and impact analysis (`worker`, `importer`, `exporter`, `alias`, `worker-base`) <br /> The determine version `indexer`<br /> `cron/` jobs for database backups and processing oss-fuzz records |
| `docs/`         | Jekyll files for https://google.github.io/osv.dev/ <br /> `build_swagger.py` and `tools.go` |
| `gcp/api`       | OSV API server files (including files for the local ESP server) <br /> protobuf files in `/v1`|
| `gcp/datastore` | The datastore index file (`index.yaml`) |
| `gcp/functions` | The Cloud Function for publishing PyPI vulnerabilities (maintained, but not developed) |
| `gcp/website  ` | The backend of the osv.dev web interface, with the frontend in `frontend3` <br /> Blog posts (in `blog`) |
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
tools and as such are not supported or endorsed by the core OSV maintainers. You may wish
to consult the [OpenSSF's Concise Guide for Evaluating Open Source Software](https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software)
to determine suitability for your use. Some popular third party tools are:

- [Cortex XSOAR](https://github.com/demisto/content)
- [dep-scan](https://github.com/AppThreat/dep-scan)
- [Dependency-Track](https://github.com/DependencyTrack/dependency-track)
- [GUAC](https://github.com/guacsec/guac)
- [OSS Review Toolkit](https://github.com/oss-review-toolkit/ort)
- [pip-audit](https://github.com/pypa/pip-audit)
- [Renovate](https://github.com/renovatebot/renovate)
- [Trivy](https://github.com/aquasecurity/trivy)
