# Repository Allowlist Sync Tool (`repo-allowlist-sync`)

`repo-allowlist-sync` is a Go command-line tool that synchronizes repository allowlist configuration files (`.yaml`) to Cloud Datastore (`RepoAllowList` entities).

## Overview

Gitter has options to enumerate affected commits with `consider_all_branches` and cherrypick detection options (`cherrypicks_introduced`, `cherrypicks_fixed`, `cherrypicks_limit`). This tool manages the Datastore allowlist index (`RepoAllowList`) that controls these behaviors on a repository level.

> [!NOTE]
> If feature flags are already enabled at the `SourceRepository` level, you do not need to add the repository to this allowlist.

The tool performs a two-way sync:

- **Upsert**: Adds new allowlist entries from the local YAML file to Datastore, or updates modified entities.
- **Delete**: Removes entities from Datastore that are no longer present in the YAML file.

## Allowlist YAML Format

The allowlist YAML configuration file accepts a list of entries with `type`, `value`, and boolean feature flag fields.
* Supported `type`s: `url`, `regex`
  * `url`: A URL to match against the repository URL.
  * `regex`: A regex pattern to match against the repository URL (Go RE2 syntax).
* Supported boolean flags: `consider_all_branches`, `cherrypicks_introduced`, `cherrypicks_fixed`, `cherrypicks_limit`, `cherrypicks` (shorthand for all 3 cherrypick flags)

```yaml
# Examples

- type: url
  value: "https://github.com/google/osv.dev.git"
  consider_all_branches: true
  cherrypicks: true

- type: url
  value: "https://github.com/google/osv.dev.git"
  consider_all_branches: true
  cherrypicks: true
  cherrypicks_fixed: false            # Overrides cherrypicks: true for fixed event

- type: regex
  value: 'github\.com/google/osv-.*'
  consider_all_branches: true
  cherrypicks_introduced: true
  cherrypicks_fixed: true
  cherrypicks_limit: true
```

> [!TIP]
> Use single quotes for regex values so you don't have to escape backslashes or other special characters.

### Normalization and Validation

- **`type: url`**: Repository URLs are automatically normalized before being saved to Datastore (removing protocol scheme, `.git` extension, and trailing slashes). For example, `https://github.com/google/osv.dev.git` is normalized to `github.com/google/osv.dev`.
- **`type: regex`**: Regular expressions are compiled and validated against Go's RE2 standard syntax. Invalid regex entries cause validation failure.
- **`cherrypicks`**: Acts as a shorthand for setting `cherrypicks_introduced`, `cherrypicks_fixed`, and `cherrypicks_limit` simultaneously. Specific `cherrypicks_<type>` fields override the shorthand value if provided.

## Usage

Run the tool using `go run`:

```bash
go run . [flags]
```

### Options & Flags

| Flag         | Default               | Description                                                       |
| ------------ | --------------------- | ----------------------------------------------------------------- |
| `--file`     | `repo_allowlist.yaml` | Path to the input YAML allowlist file                             |
| `--project`  | `oss-vdb-test`        | Target GCP Project ID                                             |
| `--dry-run`  | `true`                | When `true`, previews sync operations without modifying Datastore |
| `--validate` | `false`               | Validates YAML file and prints summary report without Datastore   |
| `--verbose`  | `true`                | Enables detailed logging of create/update/delete operations       |

### Examples

```bash
# Validate a YAML configuration file locally without touching Datastore
go run . --file=repo_allowlist.yaml --validate

# Preview changes (dry-run) against staging Datastore
go run . --project=oss-vdb-test --file=repo_allowlist_test.yaml --dry-run=true

# Apply changes (live sync) to production Datastore
go run . --project=oss-vdb --file=repo_allowlist.yaml --dry-run=false
```

## Configuration Files

| File | Target Environment | GCP Project |
| :--- | :--- | :--- |
| [`repo_allowlist.yaml`](repo_allowlist.yaml) | Production | `oss-vdb` |
| [`repo_allowlist_test.yaml`](repo_allowlist_test.yaml) | Staging | `oss-vdb-test` |

## Automation & CI/CD

Synchronization of `repo_allowlist.yaml` and `repo_allowlist_test.yaml` with Cloud Datastore is automated via Cloud Build:

- **Validation**: Run [`run_validate.sh`](run_validate.sh) to validate both `repo_allowlist.yaml` and `repo_allowlist_test.yaml` without touching Datastore.
- **Post-Merge Sync**: Pushing changes to `repo_allowlist.yaml` or `repo_allowlist_test.yaml` on `master` triggers [`repo_allowlist_build.yaml`](repo_allowlist_build.yaml), which runs [`run_update.sh`](run_update.sh) to sync `repo_allowlist.yaml` (to `oss-vdb`) and `repo_allowlist_test.yaml` (to `oss-vdb-test`).
