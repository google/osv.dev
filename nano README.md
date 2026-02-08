<img src="docs/images/osv_logo_light-full.svg" alt="OSV Logo" width="300">

# OSV (Open Source Vulnerabilities)

OSV (Open Source Vulnerabilities) is a distributed vulnerability database for open source projects.  
It provides a precise, machine-readable data format (the OSV schema) and an infrastructure to aggregate and serve vulnerability data across multiple ecosystems.

---

## 🔗 Quick Links

- **Official Website:** https://osv.dev
- **Documentation:**
  - User Guide: https://google.github.io/osv.dev/
  - API Reference: https://google.github.io/osv.dev/api/
- **Data Dumps:** Available via Google Cloud Storage at `gs://osv-vulnerabilities`
  - Learn more: https://osv.dev/docs/#data-dumps
- **Mailing List:** https://groups.google.com/g/osv-discuss

---

## 🔍 Using the Scanner

We provide a Go-based tool that scans your dependencies and matches them against the OSV database using the OSV API.

### Capabilities

- Scans lockfiles
- Scans Debian Docker containers
- Scans SBOMs (SPDX / CycloneDX)
- Scans Git repositories

### Scanner Repository

- https://github.com/google/osv-scanner

---

## 🛠 Repository Structure

This repository contains the backend infrastructure for running **osv.dev** on Google Cloud Platform (GCP).

---

## 📌 Core Components

| Component      | Description                                                       |
| -------------- | ----------------------------------------------------------------- |
| `osv/`         | Core Python library used across all services; defines data models |
| `gcp/api/`     | API server implementation and Protobuf definitions                |
| `gcp/website/` | Backend for the web interface (frontend is in `frontend3`)        |
| `gcp/workers/` | Workers for bisection, impact analysis, and database maintenance  |

---

## 🔧 Development & Integration

| Component      | Description                                                             |
| -------------- | ----------------------------------------------------------------------- |
| `bindings/`    | Language bindings (currently Go only)                                   |
| `vulnfeeds/`   | Tools for converting external feeds (NVD, Alpine, Debian) to OSV format |
| `gcp/indexer/` | Version indexer logic                                                   |
| `tools/`       | Development scripts for linting and datastore management                |

---

## ☁️ Infrastructure

| Component     | Description                                             |
| ------------- | ------------------------------------------------------- |
| `deployment/` | Terraform, Cloud Deploy, and Cloud Build configurations |
| `docker/`     | Dockerfiles for CI and worker base images               |
| `docs/`       | Jekyll-based source files for the documentation site    |

---

## 🚀 Getting Started

To build or run parts of the project locally, ensure you initialize the submodules:

```bash
git submodule update --init --recursive
```

## 🤝 Contributing

Contributions are always welcome!

Contributing Code: https://google.github.io/osv.dev/contributing/

Contributing Data: https://google.github.io/osv.dev/contributing_data/

Contributing Documentation: https://google.github.io/osv.dev/contributing_docs/

## 📦 Third-Party Integrations

The community has built several tools that integrate with the OSV database.

Note: These are community-maintained and not officially endorsed by the OSV team.

Examples
Scanners: Trivy, dep-scan, pip-audit

Management: Dependency-Track, GUAC

Automation: Renovate, OSS Review Toolkit
