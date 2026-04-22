#!/usr/bin/env python3
"""
Dependency Update PR Reviewer
This script automates the discovery, analysis, and reporting of dependency
update Pull Requests for the google/osv.dev repository.
"""

import subprocess
import json
import sys


def run_gh_command(args):
  """Executes a GitHub CLI command and returns the standard output."""
  try:
    result = subprocess.run(
        ["gh"] + args, capture_output=True, text=True, check=True)
    return result.stdout
  except subprocess.CalledProcessError as e:
    print(
        f"Error running gh command: {' '.join(args)}\n{e.stderr}",
        file=sys.stderr)
    sys.exit(1)


def main():
  """Main entry point."""
  print("Fetching open dependency PRs...", file=sys.stderr)
  prs_output = run_gh_command([
      "pr", "list", "--label", "dependencies", "--state", "open", "--json",
      "number,title,headRefName,url"
  ])
  prs = json.loads(prs_output)

  ready_prs = []
  manual_prs = []

  for pr in prs:
    pr_num = pr["number"]
    title = pr["title"]
    branch = pr["headRefName"]

    print(f"Analyzing PR {pr_num}...", file=sys.stderr)

    # 1. Check CI status using structured JSON rollup
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

    # 2. Analyze Version Jump (Heuristic: branch name contains 'major')
    is_major = "major" in branch.lower()

    # 3. Analyze files changed
    diff_output = run_gh_command(["pr", "diff", str(pr_num), "--name-only"])
    files_changed = [f for f in diff_output.strip().split('\n') if f]
    files_summary = files_changed[0] + ("..." if len(files_changed) > 1 else "")

    # 4. Determine categorization
    reasons_for_manual = []
    if failed_or_pending_checks:
      reasons_for_manual.append(
          f"Failing/Pending CI ({len(failed_or_pending_checks)} checks)")
    if is_major:
      reasons_for_manual.append("Major version jump")

    if reasons_for_manual:
      manual_prs.append({
          "number": pr_num,
          "title": title,
          "reasons": ", ".join(reasons_for_manual)
      })
    else:
      ready_prs.append({
          "number": pr_num,
          "title": title,
          "files": files_summary
      })

  # Generate Markdown Report
  print("\n### Dependency Update Review Report\n")

  print("#### ✅ Ready for Submission")
  print("These PRs are patch or minor updates with passing CI and "
        "standard file changes.")
  print("\n| PR Number | Title | Files Modified |")
  print("| :--- | :--- | :--- |")
  for pr in ready_prs:
    print(f"| {pr['number']} | {pr['title']} | `{pr['files']}` |")

  print("\n**Submission List (Easy to paste):**")
  print("```text")
  for pr in ready_prs:
    print(pr['number'])
  print("```\n")

  print("#### ⚠️ Manual Review Required")
  print("These PRs require manual intervention due to major version jumps, "
        "unusual modifications, or failing CI checks.")
  print("\n| PR Number | Title | Reason for Manual Review |")
  print("| :--- | :--- | :--- |")
  for pr in manual_prs:
    print(f"| {pr['number']} | {pr['title']} | {pr['reasons']} |")


if __name__ == "__main__":
  main()
