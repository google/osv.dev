# CVE5 Converters

In this directory you will find two tools to convert CVEs from the CVEListV5 repository to OSV format. The bulk converter is designed to convert a large number of CVEs in parallel from the CVEListV5 repository, while the single converter is designed to convert a single CVE.

These converters are a continuation of the work described in the [Introducing broad C/C++ vulnerability management support](https://osv.dev/blog/posts/introducing-broad-c-c++-support/)

See [bulk-converter/run_cvelist-converter.sh](https://github.com/google/osv.dev/blob/master/vulnfeeds/cmd/converters/cve/cve5/bulk-converter/run_cvelist-converter.sh) for how this is invoked in Production.

## Usage

### Bulk Converter

```bash
go run bulk-converter/main.go [flags]
```

#### Flags

- `-cve5-repo`: CVEListV5 directory path (default: "cvelistV5")
- `-out-dir`: Path to output results (default: "cvelist2osv")
- `-start-year`: The first in scope year to process (default: "2022")
- `-workers`: The number of concurrent workers to use for processing CVEs (default: 30)
- `-cnas-allowlist`: A comma-separated list of CNAs to process. If not provided, defaults to `cna_allowlist.txt`.

#### Description

The tool performs the following steps:
1. Walks the specified CVEListV5 directory for JSON files starting from the `start-year`.
2. Filters CVEs based on the CNA allowlist and state ("PUBLISHED").
3. Converts valid CVEs to OSV format using `cvelist2osv`.
4. Outputs the OSV records and metrics to the specified output directory.

### Single Converter

```bash
go run single-converter/main.go <path/to/cve.json> [flags]
```

#### Flags
- `-out-dir`: Path to output results (default: "cvelist2osv")

#### Description

The tool performs the following steps:
1. Reads the specified CVE JSON file.
2. Converts the CVE to OSV format using `cvelist2osv`.
3. Outputs the OSV record to the specified output directory.
