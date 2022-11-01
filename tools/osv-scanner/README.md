# Vulnerability scanner (preview)

This contains a vulnerability scanner written in Go.

This tool is currently under development and is subject to change.

## Installing

```bash
$ go install github.com/google/osv.dev/tools/osv-scanner/cmd/osv-scanner@latest
```

## Scanning an SBOM

[SPDX] and [CycloneDX] SBOMs using [Package URLs] are supported. The format is
auto-detected based on the input file contents.

[SPDX]: https://spdx.dev/
[CycloneDX]: https://cyclonedx.org/
[Package URLs]: https://github.com/package-url/purl-spec

### Example

```bash
$ go run ./cmd/osv-scanner --sbom=/path/to/your/sbom.json
```

## Scanning a lockfile

A wide range of lockfiles are supported by utilizing this [lockfile package](https://github.com/G-Rath/osv-detector/tree/main/pkg/lockfile). This is the current list of supported lockfiles:

- `Cargo.lock`        
- `package-lock.json` 
- `yarn.lock`         
- `pnpm-lock.yaml`    
- `composer.lock`     
- `Gemfile.lock`      
- `go.mod`            
- `mix.lock`          
- `pom.xml`\*         
- `requirements.txt`\*

### Example

```bash
$ go run ./cmd/osv-scanner --lockfile=/path/to/your/package-lock.json -L /path/to/another/Cargo.lock
```

## Scanning a Debian based docker image packages

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

### Example

```bash
$ go run ./cmd/osv-scanner --docker image_name:latest
```

## Scanning a directory

Given a list of directories, this tool will recursively walk through every file
to find:
- Lockfiles
- SBOMs
- git directories for the latest commit hash

and make requests to OSV to determine affected vulnerabilities.

Searching for git commit hash is intended to work with projects that use
git submodules or a similar mechanism where dependencies are checked out
as real git repositories.

### Example

```bash
$ go run ./cmd/osv-scanner /path/to/your/dir
```
## JSON output
By default osv-scanner outputs a human readable table. To have osv-scanner output JSON instead, pass the `--json` flag when calling osv-scanner. 

### Output Format
```
{
  "results": [
    {
      "filePath": "sbom:file/path/test.spdx.json",
      "packages": [
        {
          "name": "mercurial",
          "version": "4.8.2",
          "ecosystem": "pypi",
          "vulnerabilities": [
            {
              "id": "PYSEC-2019-188",
              "aliases": [
                "CVE-2019-3902"
              ]
            }
          ]
        },
        {
          "name": "ansi-regex",
          "version": "3.0.0",
          "ecosystem": "npm",
          "vulnerabilities": [
            {
              "id": "GHSA-93q8-gq69-wqmw",
              "aliases": [
                "CVE-2021-3807"
              ]
            }
          ]
        }
      ]
    },
    {
      "filePath": "lockfile:package-lock.json",
      "packages": [
        {
          "name": "async",
          "version": "2.6.3",
          "ecosystem": "npm",
          "vulnerabilities": [
            {
              "id": "GHSA-fwr7-v2mv-hh25",
              "aliases": [
                "CVE-2021-43138"
              ]
            }
          ]
        },
        {
          "name": "minimist",
          "version": "1.2.5",
          "ecosystem": "npm",
          "vulnerabilities": [
            {
              "id": "GHSA-xvch-5gv4-984h",
              "aliases": [
                "CVE-2021-44906"
              ]
            }
          ]
        }
      ]
    }
  ]
}
```