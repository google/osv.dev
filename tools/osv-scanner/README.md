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
$ go run main.go --sbom=/path/to/your/sbom.json
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

```bash
$ go run main.go --lockfile=/path/to/your/package-lock.json -L /path/to/another/Cargo.lock
```

## Scanning a Debian based docker image packages

This tool will scrape the list of installed packages in a Debian image and query for vulnerabilities on them.

Currently only Debian based docker image scanning is supported.

Requires `docker` to be installed and the tool to have permission calling it.

```bash
$ go run main.go --docker image_name:latest
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
$ go run main.go /path/to/your/dir
```
