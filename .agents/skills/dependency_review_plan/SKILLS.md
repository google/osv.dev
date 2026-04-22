# Dependency Update Review Plan - google/osv.dev

This document outlines the automated workflow for reviewing and managing dependency update Pull Requests in the `google/osv.dev` repository.

## 1. Discovery & Triage
The goal is to identify all open dependency updates.
- **Action**: Use `gh pr list` to fetch PRs with the `dependencies` label.
- **Criteria**: Filter for `state:open`.

## 2. Analysis & Review
The analysis process has been automated into a deterministic Python script: `tools/review_dependency_prs.py`. It performs the following checks:
- **CI/CD Status**: Analyzes structured JSON output from `gh pr view <pr> --json statusCheckRollup` to reliably identify pending or failing checks (ignoring `SUCCESS`, `SKIPPED`, and `NEUTRAL`).
- **Change Scope**: Uses `gh pr diff --name-only` to ensure modifications are restricted to expected files.
  - Dependency manifests (`go.mod`, `poetry.lock`, `package.json`, etc.)
  - Submodule updates
  - Dockerfile and Terraform version updates
  - GitHub Actions workflow updates (`.github/workflows/`)
- **Version Analysis**: Inspects the PR's branch name (e.g., looking for `renovate/major-...`) and PR title to identify major semantic version jumps.

## 3. Reporting
Run the `tools/review_dependency_prs.py` script to generate a final summary report categorized into:
- ✅ **Ready for Submission**: Patch or Minor updates with passing CI and standard file changes.
- ⚠️ **Manual Review Required**:
    - Major version upgrades (high risk of breaking changes).
    - PRs with failing or pending CI checks.
    - PRs modifying files outside the standard dependency manifests.

## 4. Execution (Submission)
Approved PRs will be processed using the `approve_dependency_prs.sh` script.
The Python script generates an easy-to-paste list of PR numbers.
- **Approval**: Submit a review with an "LGTM" comment.
- **Submission**: Use `gh pr merge --auto --squash` to queue the PR for merging once all requirements are met.

## 5. Notable Observations & Learnings
- **API Snapshot Tests**: The `PR-api-snapshot-tests` workflow is highly sensitive to transitive dependency changes and minor service updates. Failures here frequently necessitate manual review to ensure output formats haven't unintentionally regressed.
- **Go API Clients**: `google.golang.org/api` updates frequently across multiple services (vulnfeeds, indexer, tools).
- **Renovate Branch Patterns**: Renovate clearly signals major updates in the branch name (e.g., `renovate/major-docs`), which provides a reliable programmatic heuristic for version jumps.
