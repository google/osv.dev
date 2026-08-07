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

The allowlist YAML configuration file accepts a list of entries with `type`, `value`, and boolean feature flag fields:

```yaml
# Supported entry types: 'url' and 'regex'

# Shorthand: 'cherrypicks: true' applies to all 3 cherrypick flags (introduced, fixed, limit)
- type: url
  value: "https://github.com/google/osv.dev.git"
  consider_all_branches: true
  cherrypicks: true

# Fine-grained control with specific overrides
- type: url
  value: "https://github.com/apache/hadoop.git"
  consider_all_branches: true
  cherrypicks: true
  cherrypicks_fixed: false            # Specific override for fixed

# Regex pattern match (Go RE2 syntax)
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
- **`type: regex`**: Regular expressions are compiled and validated against Go's RE2 standard syntax. Invalid regex entries are skipped with a warning.
- **`cherrypicks`**: Acts as a shorthand for setting `cherrypicks_introduced`, `cherrypicks_fixed`, and `cherrypicks_limit` simultaneously. Specific `cherrypicks_<type>` fields override the shorthand value if provided.

## Usage

Run the tool using `go run`:

```bash
go run . [flags]
```

### Options & Flags

| Flag        | Default               | Description                                                       |
| ----------- | --------------------- | ----------------------------------------------------------------- |
| `--file`    | `repo_allowlist.yaml` | Path to the input YAML allowlist file                             |
| `--project` | `oss-vdb-test`        | Target GCP Project ID                                             |
| `--dry-run` | `true`                | When `true`, previews sync operations without modifying Datastore |
| `--verbose` | `false`               | Enables detailed logging of create/update/delete operations       |
