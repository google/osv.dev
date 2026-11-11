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
- *Future Architecture*: A migration of the database backend to **PostgreSQL** (Cloud SQL) is in progress. Cloud SQL instances are provisioned via Terraform, and the API currently serves reads from Datastore/GCS while shadow-reading PostgreSQL (see `dualread/` below); the details are still evolving. **Rule**: Any new Go code interacting with the database must be abstracted behind interfaces to facilitate this migration. Much of this abstraction is already in place—refer to the shared domain interfaces defined under [`go/internal/models/`](go/internal/models/).

### Monorepo Structure
It is structured as a multi-language monorepo:
- `go/`: Go services and utilities (importer, worker, exporter, API, website, internal libraries). **This is the primary target for active migrations from Python.**
- `osv/`: Legacy shared Python library (Datastore models, ecosystem helpers). *Now mainly used by the OSS-Fuzz workers and datafix scripts; prefer Go for new logic.*
- `gcp/`: Legacy Python workers (OSS-Fuzz), the Go indexer, Cloud Functions, and Datastore index definitions ([`gcp/datastore/index.yaml`](gcp/datastore/index.yaml)).
- `website/`: Frontend assets for the osv.dev website (`frontend3` using `pnpm`) and blog posts (`blog` using Hugo).
- `vulnfeeds/`: Vulnerability feed mirrors and converters (NVD, CVE5, Debian, Alpine, etc.) (*independent Go module*).
- `bindings/`: API bindings (*contains an independent Go module under `bindings/go`*).
- `proto/`: API protobuf definitions and the ESPv2 service configuration (`proto/v1/`).
- `docs/`: The Jekyll-based documentation site served at google.github.io/osv.dev (API docs, data sources, contributing guides).
- `deployment/`: Terraform (`deployment/terraform/`), Cloud Deploy pipelines and Kubernetes/Cloud Run manifests (`deployment/clouddeploy/`), and the Cloud Build release configs.
- `docker/`: Shared Docker images (CI, ESPv2, Terraform builder, goose migrations runner, etc.).
- `tools/`: Developer/operator tooling (lint script, API snapshot tester, datafix scripts, source sync, local Grafana).
- `external/`: Externally consumed tooling, e.g. the `ids` tool used by other advisory databases to assign OSV IDs, and PyPI reference matching (*independent Go module*).

### OSV Schema Reference
Vulnerabilities across the entire system conform to the **Open Source Vulnerability (OSV) schema**.
When AI agents need to understand the exact format, fields, and semantics of vulnerability records, refer to the local `osv-schema` submodule:
- **Full Specification**: [`osv/osv-schema/docs/schema.md`](https://github.com/ossf/osv-schema/blob/main/docs/schema.md)
- **Protobuf Definition**: [`osv/osv-schema/proto/vulnerability.proto`](https://github.com/ossf/osv-schema/blob/main/proto/vulnerability.proto)
- **JSON Schema**: [`osv/osv-schema/validation/schema.json`](https://github.com/ossf/osv-schema/blob/main/validation/schema.json)

---

## Datastore Schema & Entities
We use Google Cloud Datastore to store indices and metadata for fast querying. The primary source of truth for full vulnerability records is GCS (as protobufs), but Datastore holds crucial entities for the API and Website.

These models are primarily defined in Go ([`go/internal/database/datastore/models.go`](go/internal/database/datastore/models.go) and sibling files). The legacy Python definitions in [`osv/models.py`](osv/models.py) are still kept in sync for the kinds Python code uses (see *Consistency Testing* below); some newer kinds (e.g. `UbuntuPackageMapping`, `RepoAllowList`) exist only in Go.

> [!IMPORTANT]
> Datastore queries that filter or sort on multiple properties need a composite index. If you add such a query (in Go or Python), add the index to [`gcp/datastore/index.yaml`](gcp/datastore/index.yaml).

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

5. **`UbuntuPackageMapping` (Kind: `UbuntuPackageMapping`)**
   * **Purpose**: Used by the experimental `POST /v1experimental/ubuntu/binary-to-source` API endpoint to resolve Ubuntu binary package names to their corresponding source package names within an Ubuntu release ecosystem.
   * **Fields**: Keyed by `<normalized_ecosystem>:<binary_name>` (e.g., `Ubuntu:24.04:libcurl4`); stores `source_names` (unindexed list of corresponding Ubuntu source package names).
   * **Note**: Defined in Go ([`go/internal/database/datastore/ubuntu_package_mapping.go`](go/internal/database/datastore/ubuntu_package_mapping.go)) and populated by `ubuntubinarymapper`.

### Other Entities You Will Encounter
- **`SourceRepository`**: Configuration for each vulnerability data source (Git, REST, or GCS bucket), read by the importer. Managed as config-as-code in [`source.yaml`](source.yaml) / [`source_test.yaml`](source_test.yaml) and synced to Datastore on merge (see [`tools/sourcerepo-sync/`](tools/sourcerepo-sync/README.md)). Do not edit these entities by hand.
- **`RepoAllowList`**: Per-Git-repository overrides for commit enumeration (e.g. consider all branches, cherry-pick handling). Managed in `go/cmd/tools/repo-allowlist-sync/repo_allowlist.yaml` / `repo_allowlist_test.yaml` and synced to Datastore on merge.
- **`ImportFinding`**: Import/lint problems found for a record, served by `GET /v1experimental/importfindings/{source}`.
- **`JobData`**: Checkpoints and state for cron jobs (e.g. last run times).
- **`AliasGroup` / `UpstreamGroup` / `RelatedGroup`**: Computed relationship groups written by the `relations` job.
- **`RepoIndex` / `RepoIndexBucket`**: File-hash index of C/C++ library releases, written by the indexer (`gcp/indexer/`) and read by the API's `determineversion` endpoint.
- **`Bug`**: Legacy entity, now only written by the OSS-Fuzz pipeline (see the Python section).

---

## Setup Commands
The project uses `poetry` for Python dependency management, `pnpm` for website frontend, and Standard Go modules for Go.

- **Install Python Dependencies**:
  ```bash
  poetry install
  ```
- **Install Go Dependencies**:
  There are multiple independent Go modules in this monorepo: `go/` (main services), `vulnfeeds/`, `bindings/go/`, `external/`, `gcp/indexer/`, `docs/`, `tools/apitester/`, `tools/datastore-remover/`, and `tools/indexer-api-caller/`. Run `go mod download` (and `go test`, linters, etc.) from within the module directory you are working on:
  ```bash
  cd go && go mod download
  ```
- **Install Website Dependencies** (for frontend development):
  ```bash
  cd website/frontend3 && pnpm install
  ```
- **Initialize Git Submodules**:
  ```bash
  git submodule update --init --recursive
  ```
- **Build Protos**:
  ```bash
  make build-protos
  ```
- **PostgreSQL Codegen (`sqlc`)**:
  If you modify [`go/internal/database/postgres/queries.sql`](go/internal/database/postgres/queries.sql) or [`go/internal/database/postgres/migrations/`](go/internal/database/postgres/migrations/), regenerate the Go query code (`go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest` if not installed):
  ```bash
  cd go/internal/database/postgres && sqlc generate
  ```

---

## Code Style & Formatting
Always format and lint your code before proposing changes. The repository provides a unified script to check for style violations with smart incremental checking:

- **Run Linters & Format Checks (Smart Auto-Detect)**:
  By default, this automatically checks only the files and Go modules changed relative to `master` (or full repo if on clean master):
  ```bash
  poetry run tools/lint_and_format.sh
  ```
- **Run Full Check on Entire Repo**:
  ```bash
  poetry run tools/lint_and_format.sh --all
  ```
- **Run on Staged Changes Only**:
  ```bash
  poetry run tools/lint_and_format.sh --staged
  ```
- **Automatically Fix/Format Files**:
  ```bash
  poetry run tools/lint_and_format.sh --fix
  ```
- **Lint Specific Files**:
  ```bash
  poetry run tools/lint_and_format.sh osv/bug.py go/cmd/worker/main.go
  ```

### Python Standards
- Formatter: `yapf` (config: [`.style.yapf`](.style.yapf), runs in parallel via `-p`)
- Linter: `pylint` (config: [`.pylintrc`](.pylintrc), runs in parallel via `-j 0`)
- **Formatting Command**: To automatically format Python files, run:
  ```bash
  poetry run yapf -i <path_to_file>.py
  ```
  *(Or run `poetry run tools/lint_and_format.sh --fix`)*
- **Rule**: When running Python scripts, always use `poetry run`.

### Go Standards
- Linter: `golangci-lint`
- **Running Go Linters**: Run `golangci-lint` using `go run` directly within the module directory (e.g. `go/`, `vulnfeeds/`, or `bindings/go/`), or run `tools/lint_and_format.sh` which automatically maps changed files to the enclosing module. The pinned linter version is defined in [`tools/lint_and_format.py`](tools/lint_and_format.py) (`GOLANGCI_LINT_PKG`); use the same version when running it manually:
  ```bash
  cd go && go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.14.0 run ./...
  ```
  *(Note: Run outside the sandbox so `go run` can fetch the linter toolchain if not cached).*
- **Formatting Command**:
  ```bash
  cd go && gofmt -s -w .
  ```
- **Rule**: Go code must follow standard Go formatting guidelines.

### Git Commit Guidelines
- **Conventional Commits**: Commit messages must follow the [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/) specification (e.g., `feat:`, `fix:`, `docs:`, `refactor:`, `chore:`). PR titles are validated against this format in CI (`.github/workflows/title.yml`), and PRs are squash-merged using the title.

### Pull Request (PR) Guidelines
- **PR Description**: Follow the [pull request template](.github/PULL_REQUEST_TEMPLATE/pull_request_template.md) (Overview, Details, Testing), and clearly state if the PR is AI-assisted (see [`CONTRIBUTING.md`](CONTRIBUTING.md)).
- **PR Metadata**: Feel free to append metadata, tracking notes, or categories inside hidden HTML comments at the very end of your PR descriptions (for example, `<!-- AI-PR -->` or other tags). This keeps the rendered description page clean while preserving useful context in the raw markdown.
- **Generated Code**: Some generated files are regenerated automatically by CI bots, which open their own PRs: `go generate ./...` in `go/` (`.github/workflows/go-generate.yml`), `make build-protos` (`.github/workflows/generate-protos.yml`), and nightly API snapshot updates (`.github/workflows/snapshots.yml`). Still regenerate files your change affects, but never hand-edit generated files (`*_pb2.py`, `*.pb.go`, `queries.sql.go`, `schema_generated.json`).

---

## Testing & Local Development
To run tests and run services locally, configure the Cloud SDK and install the Firestore emulator:

```bash
gcloud auth login
gcloud auth application-default login
gcloud components install cloud-firestore-emulator
```

### Running Test Suites
Run `make help` to list all documented Make targets.
- **All Tests**: `make all-tests` (runs `lib-tests`, `vulnfeed-tests`, `bindings-tests`, and `go-tests`; it does **not** include the API integration tests)
- **Go Tests**: `make go-tests` (or run `./run_tests.sh` inside `go/`; this also runs the Go/Python Datastore model validation)
- **Python Library Tests**: `make lib-tests`
- **Vulnfeeds Tests**: `make vulnfeed-tests`
- **API Bindings Tests**: `make bindings-tests`
- **API Integration (Snapshot) Tests**: `make api-server-tests` (runs [`tools/apitester`](tools/apitester/README.md) against a locally started API server backed by the test project, or against `OSV_API_BASE_URL` if set)

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

### Go Test Conventions
- **Datastore emulator**: Packages that need the Datastore emulator must start it once per package from `TestMain` using `testutils.RunWithDatastoreEmulator(m)` (from [`go/testutils/`](go/testutils/)), rather than per test. See `go/internal/database/datastore/main_test.go` for an example.
- **HTTP recording**: Tests that hit external HTTP services use [go-vcr](https://github.com/dnaeon/go-vcr) via `testutils.SetupVCR(t)`; cassettes are stored in the package's `testdata/` directory named after the test. Cassettes are only recorded when missing, so to re-record, delete the cassette and re-run the test (with network access).
- **Slow tests**: Some expensive tests are opt-in, e.g. `RUN_COARSE_LARGE_TEST=1` for the large coarse-version test in `go/osv/ecosystem/`.

### Managing Test Expectations & Snapshots
Many tests use expected outputs saved directly in the source tree:
- **Python expected outputs**: Python tests built on `osv/tests.py` (currently the OSS-Fuzz worker and importer tests) regenerate their expected outputs when `TESTS_GENERATE=1` is set, e.g.:
  ```bash
  cd gcp/workers/oss_fuzz_worker && TESTS_GENERATE=1 ./run_tests.sh
  ```
- **Go snapshot tests**: Tests using [go-snaps](https://github.com/gkampitakis/go-snaps) (e.g. in `vulnfeeds/` and `tools/apitester/`, stored in `__snapshots__/` directories) are updated by setting `UPDATE_SNAPS=true`, e.g.:
  ```bash
  cd vulnfeeds && UPDATE_SNAPS=true go test ./...
  ```
- **Regenerate API query snapshots**: If you modify API behaviors, update query snapshots using:
  ```bash
  make update-api-snapshots
  ```
  Always inspect the resulting `git diff` to ensure the API query output changes are expected.

### Local UI & Website Development
- **Website DevServer (Go-native)**:
  Run the local Go website development server against a live flat mock dataset with hot reloading (no GCP credentials or Datastore emulator required):
  ```bash
  make run-website-devserver
  ```
  - Mock vulnerability records are located in [`go/cmd/website-devserver/testdata/`](go/cmd/website-devserver/testdata/). Add or edit `.json` records and `.meta.yaml` companion files to immediately see changes on page refresh.
- **Run against Cloud Datastore**:
  Run the Go website server against production Datastore:
  ```bash
  make run-website
  ```
  Or against staging Datastore:
  ```bash
  make run-website-staging
  ```

### Local API Server Development (Go-native)
- To run the public OSV API server locally using the native Go implementation alongside the ESPv2 proxy (which transcodes HTTP/JSON REST requests to gRPC):
  ```bash
  make run-api-server
  ```
- To run it against the staging (`oss-vdb-test`) project with PostgreSQL shadow reads enabled, use `make run-api-server-test`. This expects a PostgreSQL connection on `127.0.0.1:5432` by default; override with the `POSTGRES_*` environment variables (see the target in the [`Makefile`](Makefile)).
- Notable API environment variables: `OSV_NORMALIZE_MATCH_NAMES` (case-insensitive package name matching for ecosystems such as NuGet and crates.io), `POSTGRES_SHADOW_RATE` (fraction of requests shadow-read from PostgreSQL), and `POSTGRES_HOST/PORT/USER/PASSWORD/DB/SSLMODE`.

### Local Monitoring Development
- To preview and edit dashboards locally (Plutono, a Grafana fork, against live GMP data), run `make run-grafana-local`. See the [monitoring README](deployment/clouddeploy/gke-workers/environments/oss-vdb-test/monitoring/README.md) for how metrics and dashboards are wired together.

---

## Go Component Architecture (`go/`)
The Go component contains the active and migrated services for the OSV database. It is structured with executables in `cmd/`, private shared libraries in `internal/`, and a few importable packages at the top level:
- **`osv/ecosystem/`**: Per-ecosystem version parsing, sorting, enumeration, and coarse-version logic. This is where ecosystem support is added or changed (see the [ecosystem README](go/osv/ecosystem/README.md)). The Python `osv/ecosystems/` equivalent is legacy and only needs parity changes when OSS-Fuzz code depends on it.
- **`purl/`**: Ecosystem ↔ Package URL (PURL) mappings. New ecosystems need an entry here too.
- **`osv/clients/`**: Thin GCS and Pub/Sub client wrappers.
- **`logger/`**: Shared `slog`-based logging setup, including GCP observability client initialisation (`InitGlobalLogger`).
- **`testutils/`**: Test helpers (Datastore emulator, GCS and Pub/Sub fakes, go-vcr setup).

### Go Monorepo Docker Builds
All Go microservices are compiled using a single, unified multi-target Dockerfile (`go/Dockerfile`) which shares the workspace compilation setup.
- Due to the `replace` directive in `go/go.mod` pointing to the sibling `bindings/` library, Go Docker builds **must** mount the `bindings/` folder into the build context.
- Since the production Cloud Build steps run inside `dir: 'go'`, they leverage BuildKit's `--build-context` flag to cleanly map the sibling folder without importing other monorepo files:
  ```bash
  docker build -t osv/importer --target importer --build-context bindings=../bindings -f Dockerfile .
  ```
- For local dev testing, you can use the exact same command inside the `go/` directory.

> [!IMPORTANT]
> **Python to Go Migration**: We are actively migrating core services from Python to Go. For example, the new Go-based worker (`go/cmd/worker/`) replaces the legacy Python worker (`gcp/workers/worker/`). Always prefer modifying the Go implementation if both exist, unless instructed otherwise.

### Executables (`go/cmd/`)

1. **`api`**:
   - The public OSV gRPC API server.
   - Defined in `go/cmd/api` as a thin wrapper calling into the `go/internal/api` library.

2. **`api-devserver`**:
   - Development orchestrator command for local testing.
   - Spawns the Go API server natively in a background thread while concurrently running the `osv-esp` (ESPv2) docker container to perform HTTP/JSON to gRPC transcoding.

3. **`website`**:
   - The public OSV website server implemented in Go.
   - Defined in `go/cmd/website` and deployed to Cloud Run.

4. **`website-devserver`**:
   - Local development server for the Go website frontend.
   - Serves the website using a live flat mock dataset in `go/cmd/website-devserver/testdata/` with hot reloading (reads live from disk on every request without requiring GCP credentials or emulator).

5. **`importer`**:
   - Run as a cron job.
   - Reads from each vulnerability data source (defined as `SourceRepository` in Datastore or mapped in [`source.yaml`](source.yaml) / [`source_test.yaml`](source_test.yaml)).
   - Detects new or deleted vulnerability records.
   - Dispatches processing tasks via **GCP Pub/Sub** to the worker.

6. **`worker`**:
   - Daemon that subscribes to Pub/Sub tasks.
   - Ingests and enriches vulnerability records.
   - Computes affected Git ranges for commit-based querying.
   - Writes the enriched records to the database (GCS/Datastore).
   - Powered by a modular processing pipeline defined in [`go/internal/worker/pipeline/`](go/internal/worker/pipeline/).

7. **`exporter`**:
   - Exports the entire database to a public GCS bucket.
   - Generates a root `all.zip` file containing all records.
   - Generates ecosystem-specific `all.zip` files (e.g., `PyPI/all.zip`).
   - Outputs individual vulnerability JSON files in their respective ecosystem folders (e.g., `PyPI/GHSA-abcd-efgh.json`).

8. **`relations`**:
   - Populates relationships between vulnerabilities in the database.
   - Calculates transitive and reflective `aliases`, reflective `related` vulnerabilities, and transitive `upstream` fields.

9. **`gitter`**:
   - Git client daemon/utility to precompute and cache git operations required by other services.
   - Performs intensive Git tasks like computing commit graphs and generating patch IDs.

10. **`recoverer`**:
   - Daemon that subscribes to failed task recovery Pub/Sub messages.
   - Repairs and retries failed GCS writes, reimports missing vulnerability records from sources (via Gitter, GCS bucket, or REST), and handles GCS generation mismatches.

11. **`custommetrics`**:
   - Long-running metrics collector daemon (`go/cmd/custommetrics/`) that periodically reads batch/dataset state from Datastore (`JobData`, `SourceRepository`, `ImportFindings`) and GCS (`all.zip`, `modified_id.csv`) and exposes dataset, drift, reconciler, deleter, and linter state metrics on `:9090/metrics` for GMP/Grafana.

12. **`vanir_signatures`**:
   - Cron job orchestrated in Go (`go/cmd/vanir_signatures/` and `go/internal/vanir/`) that queries modified vulnerabilities, shells out to a minimal Python helper script (`generate_signatures.py`) to run Vanir signature generation, and writes enriched signatures back to the database.

13. **`ubuntubinarymapper`**:
   - Run as a cron job (`go/cmd/ubuntubinarymapper/`).
   - Reads `Ubuntu/modified_id.csv` from the exported GCS bucket (`gs://osv-vulnerabilities`) with a 1-hour lookback window, downloads modified Ubuntu vulnerability records (via `Ubuntu/all.zip` or individual `Ubuntu/<id>.json` files), extracts binary-to-source package name mappings from `ecosystem_specific`, and persists them to Datastore (`UbuntuPackageMapping`) alongside a `JobData` execution checkpoint (or to a local JSON file via `-output-json`).

14. **`tools/` (`reimport-tui`, `repo-allowlist-sync`)**:
   - Developer and operator CLI/TUI utilities under `go/cmd/tools/` that share the main `go/go.mod` module.
   - `reimport-tui`: Interactive TUI tool to trigger reimports for selected `SourceRepository` entities in Datastore (`make reimport-tui`). See its [README](go/cmd/tools/reimport-tui/README.md).
   - `repo-allowlist-sync`: Synchronizes the repository allowlist YAML files (`repo_allowlist.yaml` for prod, `repo_allowlist_test.yaml` for staging) to `RepoAllowList` entities in Datastore. Runs automatically via Cloud Build when those files change on `master`, so changing per-repo Git enumeration behavior is normally just a YAML PR. See its [README](go/cmd/tools/repo-allowlist-sync/README.md).

15. **Other jobs and utilities**:
   - `osv-linter-worker`: Runs the OSV linter over the exported data and writes findings to GCS and Datastore (`ImportFinding`).
   - `generatesitemap`: Generates the website sitemaps from exported vulnerability data.
   - `recordchecker`: Checks that every `Vulnerability` in Datastore has an up-to-date GCS record.
   - `staging_api_test`: Load/performance tester that replays traffic against the staging API.
   - `first_package_finder`: Finds the first package versions for Debian releases (`debian-first-version` job).
   - `extract_versions`: Extracts unique versions from an OSV `all.zip` (ad hoc utility).

### Internal Shared Libraries (`go/internal/`)
- **`api/`**: Shared package containing the core gRPC public server implementation of the OSV API.
- **`website/`**: Shared package implementing HTTP handlers, templates, routing, and search logic for the Go website frontend.
- **`worker/`**: Core engine and subscriber logic for the Go worker.
- **`importer/`**: Core importer engine (Git, REST, and GCS bucket source handling, deletion detection, reconciliation) used by `cmd/importer`.
- **`recoverer/`**: Core engine and handlers for the Go recoverer.
- **`models/`**: Storage-agnostic domain types and store interfaces. Code should depend on these, not on a concrete database package.
- **`gcs/`**: GCS helpers (fast parallel bucket listing) and GCS-backed linter/triage result stores.
- **`sharding/`**: Datastore key-range sharding used to parallelize batch jobs such as `relations`.
- **`osvutil/`**: Small shared utilities: request `batcher/`, OSV schema validation (`schema/`), `safe/` helpers, and event helpers.
- **`metrics/`**: Shared Prometheus metric definitions and HTTP `/metrics` exposition server for OSV services (`worker`, `recoverer`, `gitter`, `custommetrics`).
- **`vanir/`**: Orchestration, filtering, and domain mutation logic for Vanir signature generation.
- **`database/`**: Shared database clients and repository store implementations (`datastore/`, `postgres/`, `dualread/`, `jsonstore/`).
  - **`datastore/`**: Cloud Datastore + GCS implementation of the domain interfaces ([`go/internal/database/datastore/`](go/internal/database/datastore/)).
    - *Design Pattern*: Models here are the primary Datastore definitions. Kinds still used by Python code are kept in sync with the legacy Python models in [`osv/models.py`](osv/models.py).
    - *Consistency Testing*: To prevent synchronization drift between Go and Python database models, a database validation test is maintained under [`go/internal/database/datastore/internal/validate/`](go/internal/database/datastore/internal/validate/) (run via `run_validate.sh`).
    - *Schema Quirks (Crucial for Agents)*: In the Datastore database, the legacy term `bug` was used for vulnerabilities. Consequently, many Datastore fields still use names like `bug_id` or `bug_ids`. In the Go codebase, these are mapped to Go struct fields like `VulnID` or `VulnIDs` (e.g., `AffectedCommits` has `VulnID string datastore:"bug_id"`). Pay close attention to the `datastore:` tag when writing queries or defining new fields!
  - **`postgres/`**: PostgreSQL implementation of the domain interfaces using `sqlc` and `pgx/v5` ([`go/internal/database/postgres/`](go/internal/database/postgres/)). Schema migrations are managed with `goose` under [`go/internal/database/postgres/migrations/`](go/internal/database/postgres/migrations/) and applied automatically in CI/CD via `gcr.io/oss-vdb/goose` ([`docker/goose/`](docker/goose/)). `queries.sql.go` and `models.go` are generated by `sqlc generate` (see *Setup Commands*) and must not be edited by hand.
  - **`dualread/`**: Shadow dual-reader wrapper ([`go/internal/database/dualread/`](go/internal/database/dualread/)) that serves primary reads from Datastore/GCS while probabilistically shadowing queries (`POSTGRES_SHADOW_RATE`) to PostgreSQL in the background to compare results and latency.
  - **`jsonstore/`**: Local JSON-file-backed store used by local tooling (e.g. `ubuntubinarymapper -output-json`).
- **`gitter/`**: Client logic to interface with the Gitter caching service.

---

## Python Component Architecture (`osv/`)
The `osv` folder is a legacy shared Python package. The Python API server, importer, and worker have been removed and replaced by Go; the package is now mainly used by the OSS-Fuzz workers (`gcp/workers/oss_fuzz_*`) and the datafix scripts in `tools/datafix/`. **Prefer Go for any new logic.**

- **`models.py`**: Legacy Python Datastore models, kept in sync with the Go models for the kinds Python code still uses (validated by `go/internal/database/datastore/internal/validate/`).
  - **Note on `Bug` Entity**: The `Bug` entity inside `models.py` is **legacy and retired** for core services. The OSS-Fuzz pipeline now writes **only** `Bug` entities and publishes records to the [`oss-fuzz-vulns`](https://github.com/google/oss-fuzz-vulns) Git repository, which is then imported into OSV like any other `SourceRepository`. Nothing else should write `Bug` entities or write OSS-Fuzz data directly to the main `Vulnerability`/`AffectedCommits` kinds.
- **`bug.py`**: Helper classes and methods for representing bugs.
- **`impact.py`**: Git commit-range impact analysis, now used only by the OSS-Fuzz bisection/impact workers.
- **`ecosystems/`**: Legacy Python ecosystem version logic. The primary implementation is the Go [`go/osv/ecosystem/`](go/osv/ecosystem/README.md) package; only mirror changes here when OSS-Fuzz code needs them.

---

## GCP Component Architecture (`gcp/`)
Describes where each main service is deployed. The `gcp/` directory itself now mainly holds the legacy Python (OSS-Fuzz) workers, the Go indexer, Cloud Functions, and Datastore index definitions; deployment manifests live in `deployment/`.

### 1. API Server (`go/cmd/api/`)
- **Status**: **Active (Go)**.
- Serves the public OSV gRPC API server (transcoded to HTTP/JSON REST via ESPv2).
- **Deployment Target**: **Google Cloud Run** (managed via Cloud Deploy pipeline `osv-api` deploying to `osv-grpc-backend`).
- *Note*: Fully migrated from Python to Go. Protobuf definitions and descriptor files are located under `proto/v1/`.

### 2. Website (`go/cmd/website/`, `website/`)
- **Status**: **Active (Go)**.
- Fully migrated to Go backend under `go/cmd/website/` and `go/internal/website/`. Frontend assets (Hugo blog, pnpm frontend3) are located under `website/`.
- **Deployment Target**: **Google Cloud Run** (managed via Cloud Deploy pipeline `osv-website`).

### 3. Workers (`gcp/workers/`)
- **`worker` (`gcp/workers/worker/`)**: **Base Environment**. Retains shared Poetry dependencies and base Dockerfile for legacy Python workers; legacy worker daemon replaced by Go worker under `go/cmd/worker/`.
- **ClusterFuzz Worker (`gcp/workers/oss_fuzz_worker/`, `gcp/workers/oss_fuzz_importer/`)**: **Barely Maintained**. Siloed workloads for OSS-Fuzz integration.
  - **Deployment Target**: **GKE** (managed via Cloud Deploy pipeline `oss-fuzz-workers`).

### 4. Indexer (`gcp/indexer/`)
- **Status**: **Active (Go)**.
- Handles indexing, but is not under active development.
- **Deployment Target**: **GKE** (managed via Cloud Deploy pipeline `gke-indexer`).

### 5. Go Pipeline Workloads
- The Go importer, worker, exporter, relations, gitter, recoverer, custommetrics, vulnfeeds converters, and other cron jobs run on **GKE**, managed via the Cloud Deploy pipeline `gke-workers` (manifests under [`deployment/clouddeploy/gke-workers/`](deployment/clouddeploy/gke-workers/), with `base/` plus per-environment overlays in `environments/`).

---

## Vulnfeeds (`vulnfeeds/`)
An independent Go module containing mirrors and converters that turn upstream advisory feeds (NVD, CVE List V5, Debian, Alpine, etc.) into OSV records, which are then imported like any other data source.
- Overview and per-tool docs: [`vulnfeeds/README.md`](vulnfeeds/README.md), plus READMEs under `vulnfeeds/cmd/converters/*/` and `vulnfeeds/cmd/mirrors/*/`.
- CVE5 conversion and the per-CNA extractor / strategy pattern: [`vulnfeeds/conversion/cve5/README.md`](vulnfeeds/conversion/cve5/README.md).
- Combining NVD/CVE5 output into final records: [`vulnfeeds/cmd/combine-to-osv/DESIGN.md`](vulnfeeds/cmd/combine-to-osv/DESIGN.md).
- Tests: `make vulnfeed-tests` (snapshot tests use go-snaps; see *Managing Test Expectations & Snapshots*).

---

## Infrastructure & Deployment (`deployment/`)
See [`deployment/README.md`](deployment/README.md) for full details.
- **Environments / GCP projects**: `oss-vdb` (production), `oss-vdb-test` (staging/test), and `private-osv` (private instance). Terraform for each lives in `deployment/terraform/environments/<project>/`, built from modules in `deployment/terraform/modules/` (`osv_pipeline`, `osv_api`, `osv`, `oss_fuzz`, `k8s_cron_alert`).
- **Staging**: Pushes to `master` trigger [`deployment/build-and-stage.yaml`](deployment/build-and-stage.yaml), which builds images, applies Terraform to `oss-vdb-test`, and creates Cloud Deploy releases to staging.
- **Production**: Releases are promoted via [`deployment/deploy-prod.yaml`](deployment/deploy-prod.yaml) (triggered by release tags, see `deployment/deploy.sh`), which also promotes to the private instance.
- **Adding a new service or job**: Typically requires a new target in `go/Dockerfile`, build/tag steps and a staging release in `build-and-stage.yaml`, a promotion entry in `deploy-prod.yaml` if it is a new pipeline, and manifests under `deployment/clouddeploy/` (for GKE, `gke-workers/base/` plus environment overlays). Remember to update this file's *Executables* list too.
- **Monitoring**: Metrics are defined in `go/internal/metrics/` and scraped by Google Managed Prometheus; dashboards are served by Plutono (a Grafana 7.5 fork) and provisioned from `deployment/clouddeploy/gke-workers/environments/oss-vdb-test/monitoring/` (currently only in `oss-vdb-test`). See the [monitoring README](deployment/clouddeploy/gke-workers/environments/oss-vdb-test/monitoring/README.md).

---

## Task-Specific Documentation
Before working on one of these tasks, read the linked documentation:

| Task | Documentation |
|---|---|
| Understanding the overall architecture | [`docs/contributing/architecture.md`](docs/contributing/architecture.md) |
| Onboarding a new data source (including licensing requirements) | [`docs/new_source.md`](docs/new_source.md), [`docs/data.md`](docs/data.md), [`source.yaml`](source.yaml) / [`source_test.yaml`](source_test.yaml), [`tools/sourcerepo-sync/README.md`](tools/sourcerepo-sync/README.md) |
| Adding or changing an ecosystem (version logic, PURLs) | [`go/osv/ecosystem/README.md`](go/osv/ecosystem/README.md), [`docs/new_source.md`](docs/new_source.md) |
| REST-based data source contract | [`docs/rest-api.md`](docs/rest-api.md) |
| Record quality / linter rules | [`docs/data_quality.md`](docs/data_quality.md) |
| Changing the API (protos, endpoints, ESPv2 config) | [`proto/v1/README.md`](proto/v1/README.md), API docs in [`docs/api/`](docs/api/index.md), `make build-protos`, `make build-swagger` |
| API snapshot / integration tests | [`tools/apitester/README.md`](tools/apitester/README.md) |
| Changing per-repo Git enumeration behavior (branches, cherry-picks) | [`go/cmd/tools/repo-allowlist-sync/README.md`](go/cmd/tools/repo-allowlist-sync/README.md) |
| Reimporting or fixing records | [`go/cmd/tools/reimport-tui/README.md`](go/cmd/tools/reimport-tui/README.md), [`tools/datafix/README.md`](tools/datafix/README.md) |
| Exporter output layout | [`go/cmd/exporter/README.md`](go/cmd/exporter/README.md) |
| Vulnfeeds converters / CVE5 extraction | [`vulnfeeds/README.md`](vulnfeeds/README.md), [`vulnfeeds/conversion/cve5/README.md`](vulnfeeds/conversion/cve5/README.md) |
| Metrics and Grafana dashboards | [Monitoring README](deployment/clouddeploy/gke-workers/environments/oss-vdb-test/monitoring/README.md) |
| Terraform, Cloud Deploy, Cloud SQL setup | [`deployment/README.md`](deployment/README.md), [`docker/terraform/README.md`](docker/terraform/README.md) |
| Editing the documentation site | [`docs/README.md`](docs/README.md) |
| Writing a blog post | [`website/blog/README.md`](website/blog/README.md) |
| Contribution process | [`CONTRIBUTING.md`](CONTRIBUTING.md) |


