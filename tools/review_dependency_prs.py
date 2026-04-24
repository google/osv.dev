#!/usr/bin/env python3
"""
Dependency Update PR Reviewer
This script automates the discovery, analysis, and reporting of dependency
update Pull Requests for the google/osv.dev repository.
"""

import argparse
import json
import subprocess
import sys
from typing import Any, Dict, List

# List of file patterns or directories that are expected to be modified by
# dependency update tools (e.g., Renovate, Dependabot).
EXPECTED_DEP_FILES = [
    "go.mod",
    "go.sum",
    "package.json",
    "package-lock.json",
    "poetry.lock",
    "pyproject.toml",
    "requirements.txt",
    "Dockerfile",
    "terraform/",
    ".github/workflows/",
]


def run_gh_command(args: List[str]) -> str:
  """Executes a GitHub CLI command and returns the standard output."""
  try:
    result = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, check=True)
    return result.stdout
  except subprocess.CalledProcessError as e:
    print(
        f"Error running gh command: {' '.join(args)}\n{e.stderr}",
        file=sys.stderr,
    )
    sys.exit(1)


def is_expected_file(filename: str) -> bool:
  """Checks if a filename matches expected dependency update patterns."""
  for pattern in EXPECTED_DEP_FILES:
    if filename.startswith(pattern) or filename.endswith(pattern):
      return True
  return False


def analyze_pr(pr: Dict[str, Any]) -> Dict[str, Any]:
  """Analyzes a single PR and returns categorization and reasoning."""
  pr_num = pr["number"]
  branch = pr["headRefName"]
  reasons_for_manual = []

  # 1. Check CI status
  status_output = run_gh_command(
      ["pr", "view", str(pr_num), "--json", "statusCheckRollup"])
  status_data = json.loads(status_output)
  checks = status_data.get("statusCheckRollup", [])

  failed_or_pending_checks = []
  for check in checks:
    status = check.get("status")
    conclusion = check.get("conclusion")
    if status != "COMPLETED":
      failed_or_pending_checks.append(f"{check.get('name')} (Pending)")
    elif conclusion not in ("SUCCESS", "SKIPPED", "NEUTRAL"):
      failed_or_pending_checks.append(
          f"{check.get('name')} (Failed: {conclusion})")

  if failed_or_pending_checks:
    reasons_for_manual.append(
        f"Failing/Pending CI ({len(failed_or_pending_checks)} checks)")

  # 2. Analyze Version Jump
  if "major" in branch.lower():
    reasons_for_manual.append("Major version jump")

  # 3. Analyze files changed
  diff_output = run_gh_command(["pr", "diff", str(pr_num), "--name-only"])
  files_changed = [f for f in diff_output.strip().split("\n") if f]
  unexpected_files = [f for f in files_changed if not is_expected_file(f)]

  if unexpected_files:
    reasons_for_manual.append(
        f"Unexpected files: {', '.join(unexpected_files)}")

  files_summary = (
      files_changed[0] + ("..." if len(files_changed) > 1 else "")
      if files_changed else "No files")

  return {
      "number": pr_num,
      "title": pr["title"],
      "url": pr["url"],
      "files_summary": files_summary,
      "reasons_for_manual": reasons_for_manual,
      "is_ready": len(reasons_for_manual) == 0,
  }


def perform_pr_actions(pr_number: int, approve: bool, merge: bool):
  """Performs actions on a PR like approval and enabling auto-merge."""
  if approve:
    print(f"Approving PR {pr_number}...", file=sys.stderr)
    run_gh_command(["pr", "review", str(pr_number), "--approve", "-b", "LGTM"])

  if merge:
    print(f"Enabling auto-merge for PR {pr_number}...", file=sys.stderr)
    run_gh_command(["pr", "merge", str(pr_number), "--auto", "--squash"])


def generate_report(ready_prs: List[Dict], manual_prs: List[Dict]):
  """Generates and prints the Markdown report."""
  print("\n### Dependency Update Review Report\n")

  print("#### ✅ Ready for Submission")
  print("These PRs are patch or minor updates with passing CI and "
        "standard file changes.")
  print("\n| PR Number | Title | Files Modified |")
  print("| :--- | :--- | :--- |")
  for pr in ready_prs:
    print(f"| {pr['number']} | {pr['title']} | `{pr['files_summary']}` |")

  if ready_prs:
    print("\n**Submission List (Easy to paste):**")
    print("```text")
    print(" ".join(str(pr["number"]) for pr in ready_prs))
    print("```\n")

  print("#### ⚠️ Manual Review Required")
  print("These PRs require manual intervention due to major version jumps, "
        "unusual modifications, or failing CI checks.")
  print("\n| PR Number | Title | Reason for Manual Review |")
  print("| :--- | :--- | :--- |")
  for pr in manual_prs:
    reasons = ", ".join(pr["reasons_for_manual"])
    print(f"| {pr['number']} | {pr['title']} | {reasons} |")


def main():
  """Main entry point."""
  parser = argparse.ArgumentParser(description="Review dependency update PRs.")
  parser.add_argument(
      "--approve",
      action="store_true",
      help="Approve ready PRs (use with caution)")
  parser.add_argument(
      "--merge",
      action="store_true",
      help="Enable auto-merge for ready PRs (use with caution)",
  )
  args = parser.parse_args()

  print("Fetching open dependency PRs...", file=sys.stderr)
  prs_output = run_gh_command([
      "pr",
      "list",
      "--label",
      "dependencies",
      "--state",
      "open",
      "--json",
      "number,title,headRefName,url",
  ])
  prs = json.loads(prs_output)

  ready_prs = []
  manual_prs = []

  for pr_data in prs:
    print(f"Analyzing PR {pr_data['number']}...", file=sys.stderr)
    analysis = analyze_pr(pr_data)
    if analysis["is_ready"]:
      ready_prs.append(analysis)
      if args.approve or args.merge:
        perform_pr_actions(analysis["number"], args.approve, args.merge)
    else:
      manual_prs.append(analysis)

  generate_report(ready_prs, manual_prs)


if __name__ == "__main__":
  main()
