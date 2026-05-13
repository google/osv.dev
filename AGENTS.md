# AGENTS.md

This file provides guidance for AI coding agents working on the `osv.dev` repository. It outlines the project structure, setup commands, testing instructions, and coding standards.

> [!IMPORTANT]
> **Keeping this file up to date**: If you (an AI agent) make any major architectural changes, introduce new services, or modify core workflows (like testing or linting), you **MUST** update this `AGENTS.md` file to reflect those changes.

## Project Overview
This repository (`google/osv.dev`) contains the backend services, database models, API, and website for the Open Source Vulnerabilities (OSV) database.

### Infrastructure & Storage
- **Cloud Platform**: The entire system runs on **Google Cloud Platform (GCP)**.
- **Database (Indexes)**: We currently use **Google Cloud Datastore** to store and query indexes.
- **Database (Full Records)**: Full vulnerability records are stored as **protocol buffers (protos) in Google Cloud Storage (GCS)**.
- *Future Architecture*: There are long-term plans to migrate the database backend to **PostgreSQL**, but this is not yet concrete. **Rule**: Any new Go code interacting with the database must be abstracted behind interfaces to facilitate this eventual migration. Much of this abstraction is already in place—refer to the shared domain interfaces defined under [`go/internal/models/`](go/internal/models/).

### Monorepo Structure
It is structured as a multi-language monorepo:
- `go/`: Go services and utilities (importers, exporter, internal libraries). **This is the primary target for active migrations from Python.**
- `osv/`: Core Python library containing models, repository helpers, and ecosystem-specific logic. *Note: Some parts are deprecated as we migrate logic to Go.*
- `gcp/`: GCP deployment configurations, Cloud Functions, API server, and workers. (Website frontend uses `pnpm` and Hugo).
- `vulnfeeds/`: Vulnerability feed utilities (*independent Go module*).
- `bindings/`: API bindings (*contains an independent Go module under `bindings/go`*).

### OSV Schema Reference
Vulnerabilities across the entire system conform to the **Open Source Vulnerability (OSV) schema**.
When AI agents need to understand the exact format, fields, and semantics of vulnerability records, refer to the local `osv-schema` submodule:
- **Full Specification**: [`osv/osv-schema/docs/schema.md`](osv/osv-schema/docs/schema.md)
- **Protobuf Definition**: [`osv/osv-schema/proto/vulnerability.proto`](osv/osv-schema/proto/vulnerability.proto)
- **JSON Schema**: [`osv/osv-schema/validation/schema.json`](osv/osv-schema/validation/schema.json)

---

## Datastore Schema & Entities
We use Google Cloud Datastore to store indices and metadata for fast querying. The primary source of truth for full vulnerability records is GCS (as protobufs), but Datastore holds crucial entities for the API and Website.

These models are defined in Python ([`osv/models.py`](osv/models.py)) and mirrored in Go ([`go/internal/database/datastore/models.go`](go/internal/database/datastore/models.go)).

### Key Entities

1. **`Vulnerability` (Kind: `Vulnerability`)**
   * **Purpose**: Serves as the main index for vulnerability metadata (source, modified time, aliases, relations).
   * **Fields**: Stores `source_id` (e.g., `source:path`), `modified` time, and relation lists (`alias_raw`, `related_raw`, `upstream_raw`).

2. **`AffectedVersions` (Kind: `AffectedVersions`)**
   * **Purpose**: Used for API matching when querying by package name and version.
   * **Fields**: Contains `ecosystem`, `name` (package name), `versions` (list of affected versions), and `events` (introduced/fixed ranges).
   * **Optimization**: Uses `coarse_min` and `coarse_max` for fast range-based filtering.

3. **`AffectedCommits` (Kind: `AffectedCommits`)**
   * **Purpose**: Used for API matching when querying by Git commit.
   * **Fields**: Maps a `bug_id` (vulnerability ID, note the legacy field name) to a list of affected Git commit hashes (stored as bytes).
   * **Schema Quirk**: The field for vulnerability ID is `bug_id` in Datastore but mapped to `VulnID` in Go.

4. **`ListedVulnerability` (Kind: `ListedVulnerability`)**
   * **Purpose**: Optimized specifically for the website's `/list` page.
   * **Fields**: Contains summary, ecosystems, packages, severities, and search indices.
   * **Rule**: This entity is **only** used by the website and should not be used for API matching logic.

---

## Setup Commands
The project uses `poetry` for Python dependency management, `pnpm` for website frontend, and Standard Go modules for Go.

- **Install Python Dependencies**:
  ```bash
  poetry install
  ```
- **Install Go Dependencies**:
  There are multiple Go modules in this monorepo. Run `go mod download` from within the respective directory (`go/`, `vulnfeeds/`, or `bindings/go/`) depending on what you are working on:
  ```bash
  cd go && go mod download
  ```
- **Install Website Dependencies** (for frontend development):
  ```bash
  cd gcp/website/frontend3 && pnpm install
  ```
- **Initialize Git Submodules**:
  ```bash
  git submodule update --init --recursive
  ```
- **Build Protos**:
  ```bash
  make build-protos
  ```

---

## Code Style & Formatting
Always format and lint your code before proposing changes. The repository provides a unified script to check for style violations:

- **Run Linters & Format Checks**:
  ```bash
  poetry run tools/lint_and_format.sh
  ```
  *Note: This script only checks for violations and does not automatically format code.*

### Python Standards
- Formatter: `yapf` (config: [`.style.yapf`](.style.yapf))
- Linter: `pylint` (config: [`.pylintrc`](.pylintrc))
- **Formatting Command**: To automatically format Python files, run:
  ```bash
  poetry run yapf -i <path_to_file>.py
  ```
- **Rule**: When running Python scripts, always use `poetry run`.

### Go Standards
- Linter: `golangci-lint` (run automatically by the lint script per module).
- **Rule**: Go code must follow standard Go formatting guidelines.

### Git Commit Guidelines
- **Conventional Commits**: Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (e.g., `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`).

### Pull Request (PR) Guidelines
- **PR Metadata**: Feel free to append metadata, tracking notes, or categories inside hidden HTML comments at the very end of your PR descriptions (for example, `<!-- AI-PR -->` or other tags). This keeps the rendered description page clean while preserving useful context in the raw markdown.

---

## Testing & Local Development
To run tests and run services locally, configure the Cloud SDK and install the Firestore emulator:

```bash
gcloud auth login
gcloud auth application-default login
gcloud components install cloud-firestore-emulator
```

### Running Test Suites
- **All Tests**: `make all-tests`
- **Go Tests**: `make go-tests` (or run `./run_tests.sh` inside `go/`)
- **Python Library Tests**: `make lib-tests`

### Running Specific Tests
To save time during development, you can run specific tests instead of the entire suite:
- **Single Go Test**: Navigate to `go/` and run `go test` with `-run`:
  ```bash
  go test -v ./internal/database/datastore -run TestComputeAffectedVersions
  ```
- **Single Python Test**: From the root, run using `poetry run python -m unittest`:
  ```bash
  poetry run python -m unittest osv.bug_test.NormalizeTest.test_normalize
  ```

### Managing Test Expectations & Snapshots
Many tests use expected outputs saved directly in the source tree:
- **Regenerate Expected Test Outputs**: If you make changes that alter expected test outputs, regenerate them using:
  ```bash
  TESTS_GENERATE=1 make all-tests
  ```
- **Regenerate API query snapshots**: If you modify API behaviors, update query snapshots using:
  ```bash
  make update-api-snapshots
  ```
  Always inspect the resulting `git diff` to ensure the API query output changes are expected.

### Local UI & Datastore Emulator
- For local UI testing without GCP project credentials, run the website using a local mock dataset and a datastore emulator:
  ```bash
  make run-website-emulator
  ```
  - Add custom mock testcases inside [`gcp/website/testdata/osv/`](gcp/website/testdata/osv/).

---

## Go Component Architecture (`go/`)
The Go component contains the active and migrated services for the OSV database. It is structured with executables in `cmd/` and shared libraries in `internal/`.

> [!IMPORTANT]
> **Python to Go Migration**: We are actively migrating core services from Python to Go. For example, the new Go-based worker (`go/cmd/worker/`) replaces the legacy Python worker (`gcp/workers/worker/`). Always prefer modifying the Go implementation if both exist, unless instructed otherwise.

### Executables (`go/cmd/`)

1. **`importer`**:
   - Run as a cron job.
   - Reads from each vulnerability data source (defined as `SourceRepository` in Datastore or mapped in [`source.yaml`](source.yaml) / [`source_test.yaml`](source_test.yaml)).
   - Detects new or deleted vulnerability records.
   - Dispatches processing tasks via **GCP Pub/Sub** to the worker.

2. **`worker`**:
   - Daemon that subscribes to Pub/Sub tasks.
   - Ingests and enriches vulnerability records.
   - Computes affected Git ranges for commit-based querying.
   - Writes the enriched records to the database (GCS/Datastore).
   - Powered by a modular processing pipeline defined in [`go/internal/worker/pipeline/`](go/internal/worker/pipeline/).

3. **`exporter`**:
   - Exports the entire database to a public GCS bucket.
   - Generates a root `all.zip` file containing all records.
   - Generates ecosystem-specific `all.zip` files (e.g., `PyPI/all.zip`).
   - Outputs individual vulnerability JSON files in their respective ecosystem folders (e.g., `PyPI/GHSA-abcd-efgh.json`).

4. **`relations`**:
   - Populates relationships between vulnerabilities in the database.
   - Calculates transitive and reflective `aliases`, reflective `related` vulnerabilities, and transitive `upstream` fields.

5. **`gitter`**:
   - Git client daemon/utility to precompute and cache git operations required by other services.
   - Performs intensive Git tasks like computing commit graphs and generating patch IDs.

### Internal Shared Libraries (`go/internal/`)
- **`worker/`**: Core engine and subscriber logic for the Go worker.
- **`database/`**: Shared Datastore client and repository models (specifically [`go/internal/database/datastore/`](go/internal/database/datastore/)).
  - *Design Pattern*: Models here **mirror** the Datastore models defined in the Python library ([`osv/models.py`](osv/models.py)).
  - *Consistency Testing*: To prevent synchronization drift between Go and Python database models, a database validation test is maintained under [`go/internal/database/datastore/internal/validate/`](go/internal/database/datastore/internal/validate/) (run via `run_validate.sh`).
  - *Schema Quirks (Crucial for Agents)*: In the Datastore database, the legacy term `bug` was used for vulnerabilities. Consequently, many Datastore fields still use names like `bug_id` or `bug_ids`. In the Go codebase, these are mapped to Go struct fields like `VulnID` or `VulnIDs` (e.g., `AffectedCommits` has `VulnID string datastore:"bug_id"`). Pay close attention to the `datastore:` tag when writing queries or defining new fields!
- **`gitter/`**: Client logic to interface with the Gitter caching service.
- **`repos/`**: Shared Git repository management and utilities.

---

## Python Component Architecture (`osv/`)
The `osv` folder is a shared Python package. Since the primary API server and some workers are still in Python, this package remains highly active.

- **`models.py`**: Datastore models (e.g., `Vulnerability`, `Repository`) used by the Python API.
  - **Note on `Bug` Entity**: The `Bug` entity inside `models.py` is **legacy and retired** for core services. It is no longer used by the primary system, **except by OSS-Fuzz**.
- **`bug.py`**: Helper classes and methods for representing bugs.
- **`impact.py`**: Core engine to calculate the impact of vulnerabilities.
- **`ecosystems/`**: Ecosystem-specific logic (e.g., PyPI, Maven, NPM) for analyzing versions and ranges.

---

## GCP Component Architecture (`gcp/`)
Contains deployment setups, workers running in GKE, Cloud Functions, and the user-facing website and API.

### 1. API Server (`gcp/api/`)
- **Status**: **Active (Python)**.
- Serves the public HTTP API for querying vulnerabilities by package or version.
- **Deployment Target**: **Google Cloud Run** (managed via Cloud Deploy pipeline `osv-api`).
- *Note*: Plans exist to migrate this to Go in the near future, but it currently remains in Python.

### 2. Website (`gcp/website/`)
- **Status**: **Active**.
- Contains frontend/website code. Uses Python backend, Hugo for blog rendering, and pnpm for modern JS dependencies.
- **Deployment Target**: **Google Cloud Run** (managed via Cloud Deploy pipeline `osv-website`).

### 3. Workers (`gcp/workers/`)
- **Legacy Importer/Worker (`gcp/workers/importer/`, `gcp/workers/worker/`)**: **Retired**. These are fully replaced by the Go implementations under `go/cmd/`.
- **ClusterFuzz Worker (`gcp/workers/oss_fuzz_worker/`, `gcp/workers/oss_fuzz_importer/`)**: **Barely Maintained**. Siloed workloads for OSS-Fuzz integration.
  - **Deployment Target**: **GKE** (managed via Cloud Deploy pipeline `oss-fuzz-workers`).
- **`vanir_signatures`**: **Active (Python)**. Used for signature generation/verification.
- **`recoverer`**: **Active (Python)**. Used to recover/repair states; scheduled for migration to Go in the future.

### 4. Indexer (`gcp/indexer/`)
- **Status**: **Active (Go)**.
- Handles indexing, but is not under active development.
- **Deployment Target**: **GKE** (managed via Cloud Deploy pipeline `gke-indexer`).

