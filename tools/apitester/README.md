## About

This is a tool for tracking the responses of the osv.dev API to particular
requests, to help with reviewing data quality and matching accuracy.

Requests are provided as "cassettes" which are read using
[`go-vcr`](https://github.com/dnaeon/go-vcr) as that lets us re-use cassettes
from `osv-scanner` without sacrificing the ability to easy to craft cases
manually.

Each cassette is a YAML file in `testdata/cassettes` that stores an array of
"interactions" made up of three fields:

- `id`
- `request`
- `response`

Of these, the tool only uses the `request` field, and the `response` field will
be automatically removed as part of running tool.

## Usage

As this tool uses packages intended for being used in tests, it must be run
using `go test`:

```shell
go test ./...
```

This replays each recorded `request` in `testdata/cassettes` and capture the
response body as a snapshot using
[`go-snaps`](https://github.com/gkampitakis/go-snaps); subsequent runs will
compare the response body with the existing snapshot and report any differences.

By default, any differences in existing snapshots will be considered a failure -
you can have the snapshots updated instead by setting `UPDATE_SNAPS=true`:

```shell
UPDATE_SNAPS=true go test ./...
```

Before the test suite is actually run, the cassettes will be "cleaned" so that

- the `body` of each `request` will be formatted as a multi-line string, to make
  it easier to understand what the query parameters are
- the `response` is property is not present, to reduce the size of each cassette
