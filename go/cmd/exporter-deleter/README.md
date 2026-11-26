# OSV Exporter-deleter

The [exporter](../exporter/README.md) only ever writes files, so vulnerabilities that are deleted from OSV (or that move between ecosystems) would otherwise stay in the export bucket forever. The exporter-deleter removes them. It is deployed as the `exporter-deleter` cron job (twice a day).

## How it works

1. Read the root `ecosystems.txt` to get the list of ecosystem folders. Every other folder (e.g. `all/`, or legacy folders with a `:` suffix) is ignored.
2. For each ecosystem, read `<ECOSYSTEM>/modified_id.csv` to get the set of exported IDs. Ecosystems with a missing or empty CSV are skipped with a warning; a malformed CSV aborts the run.
3. List `<ECOSYSTEM>/` and collect every `<ID>.json` directly in the folder whose ID isn't in that set. Nothing else is touched (`all.zip`, `modified_id.csv`, `GIT/osv_git.json`, nested paths, other file types).
4. If more than `-threshold-pct` percent of the vulnerability files would be deleted, abort without deleting anything. This check also applies to `-dry-run`.
5. Delete each collected file that was last updated more than `-min-age` ago. Newer files may have been written by an export that is still running. Each delete is conditional on the object generation seen when listing, so a file rewritten in the meantime is kept.

The bucket has object versioning enabled, so deleted files can be restored for a few days.

`modified_id.csv` is the only source of truth. If a live vulnerability is ever missing from it (e.g. the exporter failed to read that record in its latest run), its JSON file may be deleted. The next exporter run (every 15 minutes) re-uploads it, so the impact is a brief 404 rather than data loss.

## Rolling out to a new environment

Run a dry run first. If there's an existing backlog of stale files above the threshold, every scheduled run will refuse to delete anything; clear it once with a manual run and a higher `-threshold-pct`:

```sh
go run . -bucket osv-test-vulnerabilities -dry-run
go run . -bucket osv-test-vulnerabilities -threshold-pct=50
```

## Running locally

```sh
# See what would be deleted, without deleting anything.
go run . -bucket osv-test-vulnerabilities -dry-run
```

### Flags

- `-bucket`: GCS bucket the exporter writes to (required).
- `-min-age`: Only delete files last updated at least this long ago (default `1h`).
- `-threshold-pct`: Refuse to delete anything if more than this percent of vulnerability files would be deleted (default `2`).
- `-dry-run`: Log what would be deleted without deleting anything.
- `-workers`: Number of concurrent list/delete operations (default `100`).
