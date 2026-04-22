# Dependency Update Review Plan - google/osv.dev

This document outlines the workflow for reviewing and managing dependency update Pull Requests in the `google/osv.dev` repository.

## 1. Discovery & Triage
Identify all open dependency updates.
- **Action**: Use `gh pr list` to fetch PRs with the `dependencies` label.
- **Criteria**: Filter for `state:open`.

## 2. Analysis & Review
Execute the analysis process using the deterministic Python script: `tools/review_dependency_prs.py`. Perform the following checks:
- **CI/CD Status**: Analyze structured JSON output from `gh pr view <pr> --json statusCheckRollup` to reliably identify pending or failing checks (ignoring `SUCCESS`, `SKIPPED`, and `NEUTRAL`).
- **Change Scope**: Use `gh pr diff --name-only` to ensure modifications are restricted to expected files:
  - Dependency manifests (`go.mod`, `poetry.lock`, `package.json`, etc.)
  - Submodule updates
  - Dockerfile and Terraform version updates
  - GitHub Actions workflow updates (`.github/workflows/`)
- **Version Analysis**: Inspect the PR's branch name (e.g., looking for `renovate/major-...`) and PR title to identify major semantic version jumps.

## 3. Reporting
Run the `tools/review_dependency_prs.py` script to generate a final summary report categorized into:
- ✅ **Ready for Submission**: Patch or Minor updates with passing CI and standard file changes.
- ⚠️ **Manual Review Required**:
    - Major version upgrades (high risk of breaking changes).
    - PRs with failing or pending CI checks.
    - PRs modifying files outside the standard dependency manifests.

## 4. Final Review
Present the final summary report to the user. Do not execute any approval or merge commands (e.g., `approve_dependency_prs.sh`, `gh pr review`, or `gh pr merge`). The user will use the provided report to manually trigger any necessary scripts or actions.

## 5. Notable Observations & Learnings
Consider the following during the review process:
- **API Snapshot Tests**: Monitor the `PR-api-snapshot-tests` workflow, as it is highly sensitive to transitive dependency changes. Manual review is required if it fails to ensure output formats haven't regressed.
- **Go API Clients**: Expect frequent updates to `google.golang.org/api` across multiple services (vulnfeeds, indexer, tools).
- **Renovate Branch Patterns**: Use Renovate branch names (e.g., `renovate/major-docs`) as a reliable heuristic for identifying major version jumps.