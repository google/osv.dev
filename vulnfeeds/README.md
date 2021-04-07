# Vuln feeds
This searches a NVD CVE JSON feed for relevant packages and creates
vulnerability entries in the same easy-to-consume format that OSV uses.

## Package name matching
CVE entries do not provide an easy mapping to the exact package name used in a
package manager, so we dump and compare reference URLs for the package against
reference URLs used in the CVE, in addition to some other heuristics to avoid
false positives.

## PyPI
For PyPI, we find package reference URLs by doing a BigQuery query on
the public PyPI dataset:

```bash
bq query --max_rows=10000000 --format=json --nouse_legacy_sql --flagfile=pypi.sql > pypi.json
```

However this includes packages that no longer exist or were deleted, so we check
against the [pypi simple API](https://warehouse.pypa.io/api-reference/legacy.html)
to make sure any matches actually exist.

## Extracting affected versions and commits
Where possible, we try to extract affected version ranges from descriptions and
other fields, and extract commit hashes from e.g. GitHub links.
