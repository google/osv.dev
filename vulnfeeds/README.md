# Vuln feeds
This searches a NVD CVE JSON feed for relevant packages and creates
vulnerability entries in the same easy-to-consume format that OSV uses.

See the relevant subdirectories for more details specific to that package
ecosystem.

## Package name matching
CVE entries do not provide an easy mapping to the exact package name used in a
package manager, so we dump and compare reference URLs for the package against
reference URLs used in the CVE, in addition to some other heuristics to avoid
false positives.

## Extracting affected versions and commits
Where possible, we try to extract affected version ranges from
descriptions (pattern matching) and other fields. We also extract
commit hashes from e.g. GitHub links.

Extracted version numbers are cross referenced against the list of actual
versions released in the package manager to ensure accuracy.

## Workflow

The intended workflow is for a human to periodically run the tools here against
the latest NVD CVE feeds.

(See the [PyPI directory](pypi/) for details on how to generate the required pypi
input files (pypi_links.json, pypi_versions.json)).

```bash
export VULNS_REPO=/path/to/vulns/repo
go run ./cmd/pypi -false_positives $VULNS_REPO/triage/false_positives.txt \
    -nvd_json /path/to/nvdcve-1.1-2021.json \
    -pypi_links pypi/pypi_links.json \
    -pypi_versions pypi/pypi_versions.json \
    -out_dir $VULNS_REPO/vulns
```

This auto-generates matching `<ID>.yaml` files into `$VULNS_REPO/vulns`.

However, human intervention will always be required in some cases, when versions
cannot be reliably extracted automatically from CVE data. In these cases a
corresponding `<ID>.notes` file will be generated alongside the `<ID>.yaml` file to
indicate that a human should look at this.

An example `<ID>.notes` file will look like:

```
Warning: 2017.5.0 is not a valid introduced version
Warning: 2018.2.0 is not a valid introduced version
Warning: 3000.0 is not a valid introduced version
```

These files should be removed once resolved and not commited into the repo.
Subsequent runs of the tool will **not** overwrite existing `.yaml` files to
preserve human edits.

### False positives

False positives (i.e. CVEs that are incorrectly matched to a package) can be
added into a `false_positives.txt` file and commited as part of the
vulnerability repo for future runs.

The format of this file is newline delimited CVE IDs.

e.g.

```
CVE-2021-1337
CVE-2021-1338
...
```
