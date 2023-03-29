[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/google/osv.dev/badge)](https://api.securityscorecards.dev/projects/github.com/google/osv.dev)

## Viewing the web UI

An instance of OSV's web UI is deployed at <https://osv.dev>.

## Using the scanner

We provide a Go based tool that will scan your dependencies, and check them
against the OSV database for known vulnerabilities via the OSV API.

Currently it is able to scan various lockfiles, debian docker containers, SPDX
and CycloneDB SBOMs, and git repositories.

The scanner is located in it's
[own repository here](https://github.com/google/osv-scanner).

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
We also have a [mailing list](https://groups.google.com/g/osv-discuss).

Do you have a question or a suggestion? Please [open an issue](https://github.com/google/osv.dev/issues). 