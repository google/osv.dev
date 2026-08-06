# Repo Consider All Branches Allowlist Sync Tool (`repo-cab-sync`)

`repo-cab-sync` is a Go command-line tool that synchronizes repository "Consider All Branches" (CAB) allowlist configuration files (`.yaml`) to Cloud Datastore (`RepoConsiderAllBranchesAllowList` entities).

## Overview

Gitter has the option to enumerate affected commits with `consider_all_branches` enabled or disabled. This tool manages the Datastore allowlist index (`RepoConsiderAllBranchesAllowList`) that controls this behavior on a repository level.

> [!NOTE]
> If `consider_all_branches` is already enabled at the `SourceRepository` level, you do not need to add the repository to this allowlist.

The tool performs a two-way sync:

- **Upsert**: Adds new allowlist entries from the local YAML file to Datastore, or updates modified entities.
- **Delete**: Removes entities from Datastore that are no longer present in the YAML file.

## Allowlist YAML Format

The allowlist YAML configuration file accepts a list of entries with `type` and `value` fields:

```yaml
# Supported entry types: 'url' and 'regex'

# Exact repository URL match
- type: url
  value: "https://github.com/google/osv.dev.git"

# Regex pattern match (Go RE2 syntax)
- type: regex
  value: 'github\.com/google/osv-.*'
```

> [!TIP]
> Use single quotes for regex values so you don't have to escape backslashes or other special characters.

### Normalization and Validation

- **`type: url`**: Repository URLs are automatically normalized before being saved to Datastore (removing protocol scheme, `.git` extension, and trailing slashes). For example, `https://github.com/google/osv.dev.git` is normalized to `github.com/google/osv.dev`.
- **`type: regex`**: Regular expressions are compiled and validated against Go's RE2 standard syntax. Invalid regex entries are skipped with a warning.

## Usage

Run the tool using `go run`:

```bash
go run . [flags]
```

### Options & Flags

| Flag        | Default                   | Description                                                       |
| ----------- | ------------------------- | ----------------------------------------------------------------- |
| `--file`    | `repo_cab_allowlist.yaml` | Path to the input YAML allowlist file                             |
| `--project` | `oss-vdb-test`            | Target GCP Project ID                                             |
| `--dry-run` | `true`                    | When `true`, previews sync operations without modifying Datastore |
| `--verbose` | `false`                   | Enables detailed logging of create/update/delete operations       |
