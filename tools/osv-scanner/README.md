# Vulnerability scanner (preview)

This contains a vulnerability scanner written in Go.

This tool is currently under development and is subject to change.

## Installing

```bash
$ go install github.com/google/osv.dev/tools/osv-scanner@latest
```

## Scanning an SBOM

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents.

[SPDX]: https://spdx.dev/
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

```bash
$ go run main.go /path/to/your/sbom.json
```

## Scanning a directory

Given a list of directories, this tool will recursively search for git
repositories and make requests to OSV to determine affected vulnerabilities.

This is intended to work with projects that use git submodules or a similar
mechanism where dependencies are checked out as real git repositories.

### Example

```bash
$ go run main.go /path/to/your/repo
```
