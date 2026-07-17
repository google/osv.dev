# OSV Reimport TUI

A terminal user interface (TUI) tool written in Go (using the Bubble Tea framework) that allows developers to trigger a full reimport of vulnerability sources in either the OSV Test (`oss-vdb-test`) or Prod (`oss-vdb`) Datastore.

## Why is this needed?

Normally, the OSV Importer checks the latest commit hash (for Git sources) or the last modified time (for Buckets/REST feeds) and only imports new or modified records. 

If you need to force a full reimport (e.g. after schema changes or to repair corrupt index states), this tool allows you to:
* **Git Sources**: Clear the `LastSyncedCommit` field (forcing the importer to perform a full diff against `nil`).
* **Bucket & REST Sources**: Set the `IgnoreLastImportTime` field to `true` (forcing the importer to reprocess all files once).

---

## Features

* **Environment Selection**: Quickly toggle between Test and Production databases.
* **Fuzzy Filtering**: Type keywords to search and filter the list of sources.
* **Interactive Selection**: Select multiple sources with `Space` and navigate using the arrow keys.
* **Layout Stability**: Scrolling viewport designed to keep terminal heights stable and prevent scroll overflow.
* **Safe Confirmation & Summary**: Review selected changes before applying them, with summaries optimized for large updates.

---

## Usage

Before running, ensure you have logged into your GCP account and set up Application Default Credentials:

```bash
gcloud auth application-default login
```

Then, run the tool from the repository root:

```bash
make reimport-tui
```

---

## Development Notes

This tool is defined as a nested Go module (`go/cmd/tools/reimport-tui`) to avoid polluting the main `go/go.mod` file with Bubble Tea and Lipgloss dependencies. It still imports shared `internal` datastore packages from the parent Go module using Go's import path inheritance rules.

*This tool was entirely vibecoded by AI.*
