# Contributing to OSV.dev

Thank you for your interest in the Open Source Vulnerability (OSV) project. To maintain the integrity of our security data and code quality, please adhere to the following professional standards and technical workflows.

---

## ⚖️ Legal & Ethical Framework

### 1. Contributor License Agreement (CLA)

All contributions must be accompanied by a signed [Contributor License Agreement](https://cla.developers.google.com).

- **Ownership:** You (or your employer) retain the copyright; the CLA simply grants us permission to distribute your work.

- **Verification:** You generally only need to submit this once. Check your status or sign a new one at the [Google Developers CLA portal](https://cla.developers.google.com).

### 2. Community Guidelines

We uphold a professional environment governed by [Google’s Open Source Community Guidelines](https://opensource.google.com). Respectful collaboration is mandatory for all participants.

---

## 🛠️ Technical Workflow

### Code Review Process

We utilize [GitHub Pull Requests](https://help.github.com) for all submissions, including those from project members.

- **Feature Alignment:** For new features, [create an issue](https://github.com) for architectural discussion before beginning development.

- **Documentation:** Use our [Pull Request Template](/.github/PULL_REQUEST_TEMPLATE/pull_request_template.md) to ensure a streamlined review.

### Development Environment Setup

Ensure your system meets the following high-level prerequisites:

- **Languages:** Python 3.13 & Node.js (≥ 18.17.x)

- **Package Management:** [Poetry](https://python-poetry.org) (≥ 2.2.1)

- **Infrastructure:** [Docker](https://www.docker.com), [Terraform](https://developer.hashicorp.com) (≥ 1.5), and [Google Cloud SDK](https://cloud.google.com).

- **Build Tools:** [Make](https://www.gnu.org) and [Hugo](https://gohugo.io).

**Initialization:**

```shell

git clone --recurse-submodules https://github.com
cd osv.dev
poetry install && poetry self add poetry-plugin-shell && poetry shell

```

1. Testing Protocols

Validate your changes using our test result generation framework.
Authentication: gcloud auth login --update-adc
Standard Tests: make all-tests
API Integration: make api-server-tests
Output Regeneration: If logic changes alter expected results, use TESTS_GENERATE=1 make all-tests.

2. Linting & Formatting

Maintain code health with Pylint and Yapf.
Lint: make lint
Format: yapf -i <file>.py

3. Commit Standards

Follow the Conventional Commits specification. Use structured prefixes such as feat:, fix:, docs:, and chore: to facilitate automated changelog management.

🚀 Advanced Contribution Guidelines (Add-ons)

🛡️ Security Vulnerability Reporting (SECURITY.md)

Private Disclosure: Do not report security vulnerabilities via public GitHub issues.
Process: Please follow our Security Policy for private reporting instructions. This ensures we can patch the vulnerability before it is publicly exploited.

🗺️ Project Roadmap & Vision

Strategic Alignment: Before starting work on large features, check our Roadmap to ensure your idea aligns with the project's current direction.

"No" is Temporary: If a PR is rejected for being "out of scope," it doesn't mean it's a bad idea; it just may not fit the current 3–6 month vision.

🏷️ Issue Labeling System

To help you find the right task, we use specific labels:

good first issue: Simple tasks designed for newcomers to get familiar with our codebase.

help wanted: Critical tasks that the core team doesn't have immediate bandwidth to tackle.

datasource: Specifically for contributors adding new security advisory sources.

🤖 Automation & CI/CD

Status Checks: Every PR triggers an automated suite of tests. All checks must pass (green checkmark) before a maintainer will perform a deep manual review.

Coverage: We encourage contributors to include unit tests with every code change to maintain our high test coverage standards.

🌟 Recognition & Attribution

Public Credit: Significant contributions are celebrated in our Release Notes.

Community Roles: Consistent, high-quality contributors may be invited to join the project as Maintainers or Core Members with merge privileges.

🕒 Communication & Expectations

Response Times: We aim to review all PRs within 3–5 business days. If you haven't heard from us by then, feel free to ping the thread with a polite "Any updates?".

Asynchronous Culture: Our team works across multiple time zones; please keep all technical discussions in public PR comments or issues to ensure transparency.

Would you like me to help you set up a **GitHub Action** to automatically verify these **CLA signatures** or **Conventional Commits** on every new pull request?
