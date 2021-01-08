# OSV - Open Source Vulnerabilities

OSV is a vulnerability database for open source projects. It exposes an API that
lets users of these projects query whether or not their versions are impacted.

## Using the API

Documentation for using the API can be found at
<https://osv.dev/docs/index.html>.

## This repository

This repository contains all the code for running OSV on GCP. This consists of:

- API server (`gcp/api`)
- Web interface (`gcp/appengine`)
- Workers for bisection and impact analysis (`docker/worker`)
- Sample tools (`tools`)

Contributions are welcome!
