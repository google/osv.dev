## About

This is a tool for tracking the responses of the osv.dev API to particular
requests, to help with reviewing data quality and matching accuracy.

Requests are provided as "cassettes" which are read using
[`go-vcr`](https://github.com/dnaeon/go-vcr) as that lets us re-use cassettes
from `osv-scanner` without sacrificing the ability to easy to craft cases
manually.

Each cassette is a YAML file in `testdata/cassettes` that stores an array of
"interactions" made up of an `id`, a `request`, and a `response`, though ony the
`request` field is used by this tool.

The `request` in each interaction for a cassette is replayed and the response
body captured as a snapshot for the particular cassette using
[`go-snaps`](https://github.com/gkampitakis/go-snaps) - subsequent runs will
compare the response body with the existing snapshot and show a diff of any
differences.

## Usage

As this tool uses packages intended for being used in tests, it must be run
using `go test`:

```shell
go test ./...
```

You can regenerate snapshots by setting `UPDATE_SNAPS=true` when running tests:

```shell
UPDATE_SNAPS=true go test ./...
```
