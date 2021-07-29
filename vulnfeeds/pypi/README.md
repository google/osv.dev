# PyPI

## Reference matching
For PyPI, we find package reference URLs by doing a BigQuery query on
the public PyPI dataset.

```bash
bq query --max_rows=10000000 --format=json --nouse_legacy_sql < pypi_links.sql > pypi_links.json
```

This is also continuously updated and available at
<https://storage.googleapis.com/pypa-advisory-db/triage/pypi_links.json>

However this includes packages that no longer exist or were deleted, so we check
against the [pypi simple API](https://warehouse.pypa.io/api-reference/legacy.html)
to make sure any matches actually exist.

## Version matching
We also extract all valid versions by doing:

```bash
bq query --max_rows=10000000 --format=json --nouse_legacy_sql < pypi_versions.sql > pypi_versions.json
```

This is also continuously updated and available at
<https://storage.googleapis.com/pypa-advisory-db/triage/pypi_versions.json>
