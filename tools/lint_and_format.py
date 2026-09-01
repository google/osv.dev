#!/usr/bin/env python3
# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Unified linting and formatting script for osv.dev.

Supports smart incremental checking (auto-detecting changed files relative
to the base branch), explicit modes (--all, --changed, --staged, --fix),
and per-subsystem (Python, Go, Terraform) filtering and prerequisite checks.

Base Branch Discovery:
  - In CI (Pull Requests): Reads $GITHUB_BASE_REF (e.g. 'master') and diffs
    against 'origin/$GITHUB_BASE_REF'.
  - In CI (Push to master): Defaults to full scan (--all).
  - Locally: Checks git references in order:
      1. Custom base via --base <ref> or -c <ref>
      2. 'upstream/master' (typical for fork workflows)
      3. 'origin/master'
      4. 'master'
      5. 'upstream/main', 'origin/main', 'main'
  - If changes exist relative to the detected base branch, incremental mode
    is used. If working tree is clean and on master, full scan (--all) runs.

Change Detection Mechanics:
  - Computes `git merge-base <base> HEAD` to find the fork commit.
  - Collects committed changes since merge-base, staged changes, unstaged
    working tree modifications, and untracked files.
  - Excludes deleted files (--diff-filter=d) so linters don't error on missing
    files.

Subsystem File Tracking:
  - Python (pylint, yapf):
      * Tracked: '*.py' excluding '*_pb2.py' (protos) and 'third_party/'.
      * Config triggers: If '.pylintrc', '.style.yapf', or 'pyproject.toml'
        are modified, all Python files are checked.
      * Skipped (0.0s) when no in-scope Python files changed.
  - Go (golangci-lint, gofmt):
      * Tracked: '*.go', 'go.mod', 'go.sum',
        '*.golangci.yaml', '*.golangci.yml'.
      * Module resolution: Walks up parent directories to find the nearest
        'go.mod' (excluding 'docs/').
      * Skipped (0.0s) when no in-scope Go modules changed.
  - Terraform (terraform fmt):
      * Tracked: '*.tf', '*.tfvars', and any files in 'deployment/terraform/'.
      * Skipped (0.0s) when no Terraform files changed.
"""

import argparse
import enum
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import List, Optional, Set, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent


class LintMode(enum.Enum):
  """Execution mode for linting and formatting checks."""
  AUTO = enum.auto()
  ALL = enum.auto()
  CHANGED = enum.auto()
  STAGED = enum.auto()


def run_cmd(
    cmd: List[str],
    cwd: Optional[Path] = None,
    check: bool = False,
    capture_output: bool = False,
) -> subprocess.CompletedProcess:
  """Runs a command with convenient defaults."""
  return subprocess.run(
      cmd,
      cwd=cwd or REPO_ROOT,
      check=check,
      text=True,
      capture_output=capture_output,
  )


def git_cmd(args: List[str]) -> str:
  """Runs a git command and returns stripped stdout."""
  res = run_cmd(['git'] + args, capture_output=True, check=True)
  return res.stdout.strip()


def ref_exists(ref: str) -> bool:
  """Checks if a git reference exists."""
  res = run_cmd(
      ['git', 'rev-parse', '--verify', '--quiet', ref],
      capture_output=True,
  )
  return res.returncode == 0


def find_base_ref(custom_base: Optional[str] = None) -> Optional[str]:
  """Determines the appropriate base branch/ref to diff against."""
  if custom_base:
    return custom_base

  # Check GitHub Actions PR target branch
  gh_base = os.environ.get('GITHUB_BASE_REF')
  if gh_base:
    origin_base = f"origin/{gh_base}"
    # Fetch if needed (e.g. shallow clone)
    if not ref_exists(origin_base):
      run_cmd(
          ['git', 'fetch', 'origin', gh_base, '--depth=50'],
          capture_output=True,
      )
    if ref_exists(origin_base):
      return origin_base
    return gh_base

  # Local branch detection: prioritize upstream, then origin, then local master
  candidates = [
      'upstream/master',
      'origin/master',
      'master',
      'upstream/main',
      'origin/main',
      'main',
  ]
  for ref in candidates:
    if ref_exists(ref):
      return ref

  return None


def get_all_python_files() -> List[str]:
  """Returns all in-scope Python files in the repository."""
  output = git_cmd(
      ['ls-files', '--cached', '--others', '--exclude-standard', '*.py'])
  files = []
  for f in output.splitlines():
    f = f.strip()
    if f and '_pb2' not in f and 'third_party' not in f:
      if (REPO_ROOT / f).is_file():
        files.append(f)
  return sorted(files)


def get_all_go_modules() -> List[str]:
  """Returns all in-scope Go module directory paths."""
  output = git_cmd(['ls-files', '*/go.mod', 'go.mod'])
  modules = set()
  for path_str in output.splitlines():
    p = Path(path_str.strip())
    mod_dir = p.parent
    # Explicitly exclude docs module
    if 'docs' in mod_dir.parts:
      continue
    modules.add(str(mod_dir))
  return sorted(modules)


def find_go_module(file_path: Path, all_modules: Set[str]) -> Optional[str]:
  """Finds the nearest parent directory containing go.mod for a file."""
  if file_path.is_absolute():
    try:
      file_path = file_path.relative_to(REPO_ROOT)
    except ValueError:
      return None
  current = (
      file_path if (REPO_ROOT / file_path).is_dir() else file_path.parent)
  while current != current.parent:
    if str(current) in all_modules:
      return str(current)
    current = current.parent
  return '.' if '.' in all_modules else None


def get_changed_files_for_ref(
    base_ref: str,) -> Tuple[List[str], Optional[str]]:
  """Returns changed files relative to base_ref using merge-base."""
  merge_base = None
  res = run_cmd(['git', 'merge-base', base_ref, 'HEAD'], capture_output=True)
  if res.returncode == 0 and res.stdout.strip():
    merge_base = res.stdout.strip()
    diff_target = merge_base
  else:
    diff_target = base_ref

  diff_output = git_cmd(['diff', '--name-only', diff_target])
  untracked_output = git_cmd(['ls-files', '--others', '--exclude-standard'])

  changed = set()
  for line in (diff_output + '\n' + untracked_output).splitlines():
    line = line.strip()
    if line:
      changed.add(line)

  return sorted(changed), merge_base


def get_staged_files() -> List[str]:
  """Returns all currently staged files."""
  output = git_cmd(['diff', '--cached', '--name-only'])
  return [f.strip() for f in output.splitlines() if f.strip()]


def is_python_file(path_str: str) -> bool:
  """Checks if a path is an in-scope Python file."""
  return (path_str.endswith('.py') and '_pb2' not in path_str and
          'third_party' not in path_str and (REPO_ROOT / path_str).is_file())


def is_go_file(path_str: str) -> bool:
  """Checks if a path is an in-scope Go file."""
  return (path_str.endswith(('.go', '.golangci.yaml', '.golangci.yml')) or
          path_str.endswith('go.mod') or path_str.endswith('go.sum'))


def is_terraform_file(path_str: str) -> bool:
  """Checks if a path is an in-scope Terraform file."""
  return (path_str.startswith('deployment/terraform/') or path_str.endswith(
      ('.tf', '.tfvars')))


def categorize_files(
    files: List[Path],
    all_go_mods: Set[str],
) -> Tuple[List[str], List[str], bool]:
  """Categorizes files into Python files, Go modules, and Terraform status."""
  py_files = set()
  go_mods = set()
  run_tf = False

  for p in files:
    s = str(p)
    if is_python_file(s):
      py_files.add(s)
    if is_go_file(s):
      mod = find_go_module(p, all_go_mods)
      if mod:
        go_mods.add(mod)
    if is_terraform_file(s):
      run_tf = True

  return sorted(py_files), sorted(go_mods), run_tf


def resolve_targets(
    mode: LintMode,
    base_ref: Optional[str],
    explicit_files: List[str],
) -> Tuple[List[str], List[str], bool, str]:
  """Resolves Python files, Go modules, and Terraform status based on mode."""
  all_py_files = get_all_python_files()
  all_go_mods = set(get_all_go_modules())

  # 1. Explicit files / directories mode
  if explicit_files:
    expanded: List[Path] = []
    for file_str in explicit_files:
      p = Path(file_str)
      if not p.is_absolute():
        p = (Path.cwd() / p).resolve()
      try:
        rel_p = p.relative_to(REPO_ROOT)
      except ValueError:
        print(f"Warning: Skipping '{file_str}' (outside repository root).")
        continue

      full_p = REPO_ROOT / rel_p
      if full_p.is_dir():
        for child in full_p.rglob('*'):
          if child.is_file():
            expanded.append(child.relative_to(REPO_ROOT))
      else:
        expanded.append(rel_p)

    py_files, go_mods, run_tf = categorize_files(expanded, all_go_mods)
    return py_files, go_mods, run_tf, 'Explicit Files Mode'

  # 2. Smart auto-detection if AUTO
  if mode == LintMode.AUTO:
    if os.environ.get('GITHUB_BASE_REF'):
      mode = LintMode.CHANGED
    elif (os.environ.get('GITHUB_ACTIONS') == 'true' and
          os.environ.get('GITHUB_EVENT_NAME') != 'pull_request'):
      mode = LintMode.ALL
    else:
      detected = find_base_ref(base_ref)
      if detected and get_changed_files_for_ref(detected)[0]:
        mode = LintMode.CHANGED
        base_ref = detected
      else:
        mode = LintMode.ALL

  # 3. Full scan mode
  if mode == LintMode.ALL:
    return all_py_files, sorted(all_go_mods), True, 'Full Scan (all files)'

  # 4. Staged or Changed modes
  if mode == LintMode.STAGED:
    changed_files = [Path(f) for f in get_staged_files()]
    desc = 'Incremental Scan (staged files)'
  else:  # LintMode.CHANGED
    detected_base = find_base_ref(base_ref)
    if not detected_base:
      print('Warning: Could not detect base branch. Falling back to full scan.')
      return (
          all_py_files,
          sorted(all_go_mods),
          True,
          'Full Scan (all files, fallback)',
      )
    changed_strs, merge_base = get_changed_files_for_ref(detected_base)
    changed_files = [Path(f) for f in changed_strs]
    mb_short = f" @ {merge_base[:8]}" if merge_base else ''
    desc = f"Incremental Scan (diff against {detected_base}{mb_short})"

  py_files, go_mods, run_tf = categorize_files(changed_files, all_go_mods)

  # If Python global configs changed, check all Python files
  if any(
      str(p) in {'.pylintrc', '.style.yapf', 'pyproject.toml'}
      for p in changed_files):
    print('[Python] Global config changed; checking all Python files.')
    py_files = all_py_files

  return py_files, go_mods, run_tf, desc


def check_prerequisites(has_py: bool, has_go: bool, has_tf: bool) -> bool:
  """Validates that necessary tools exist in PATH."""
  missing = []
  if has_py:
    for tool in ('pylint', 'yapf'):
      if not shutil.which(tool):
        missing.append(tool)
  if has_go:
    if not shutil.which('go'):
      missing.append('go')
  if has_tf:
    if not shutil.which('terraform'):
      missing.append('terraform')

  if missing:
    print(
        f"Error: Prerequisite tool(s) not found in PATH: {', '.join(missing)}",
        file=sys.stderr,
    )
    print(
        "Please ensure required tools are installed, or run in 'poetry run'.",
        file=sys.stderr,
    )
    print(
        'See: https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md',
        file=sys.stderr,
    )
    return False
  return True


GOLANGCI_LINT_PKG = (
    'github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.4.0')
GOLANGCI_LINT_CMD = ['go', 'run', GOLANGCI_LINT_PKG]


def main() -> int:
  parser = argparse.ArgumentParser(
      description=(
          'Run linters and format checks on Python, Go, and Terraform files.'),
      formatter_class=argparse.RawDescriptionHelpFormatter,
      epilog="""
Examples:
  ./tools/lint_and_format.py            # Auto-detect (changed files if on branch/dirty)
  ./tools/lint_and_format.py --all            # Run full check on all files
  ./tools/lint_and_format.py --staged         # Check only files staged for commit
  ./tools/lint_and_format.py -c main    # Check files changed compared to 'main'
  ./tools/lint_and_format.py --fix      # Auto-format changed files
  ./tools/lint_and_format.py osv/bug.py # Check a specific file
""",
  )
  parser.add_argument(
      '-a',
      '--all',
      dest='mode_all',
      action='store_true',
      help='Lint all in-scope files across the entire repository',
  )
  parser.add_argument(
      '-c',
      '--changed',
      dest='custom_changed',
      nargs='?',
      const='',
      default=None,
      help='Lint only files changed relative to base (optional ref)',
  )
  parser.add_argument(
      '-s',
      '--staged',
      dest='mode_staged',
      action='store_true',
      help='Lint only git staged files',
  )
  parser.add_argument(
      '-b',
      '--base',
      dest='base_ref',
      default=None,
      help='Specify the base branch/commit to diff against',
  )
  parser.add_argument(
      '-f',
      '--fix',
      action='store_true',
      help='Auto format files where supported (yapf, terraform, gofmt)',
  )
  parser.add_argument(
      'files',
      nargs='*',
      help='Specific files or directories to lint',
  )

  args = parser.parse_args()

  # Determine mode
  if args.mode_all:
    mode = LintMode.ALL
  elif args.mode_staged:
    mode = LintMode.STAGED
  elif args.custom_changed is not None:
    mode = LintMode.CHANGED
    if args.custom_changed:
      args.base_ref = args.custom_changed
  else:
    mode = LintMode.AUTO

  py_files, go_mods, run_tf, description = resolve_targets(
      mode, args.base_ref, args.files)

  print(f"=== Lint and Format: {description} ===")

  if not check_prerequisites(bool(py_files), bool(go_mods), run_tf):
    return 1

  findings = []

  # --- 1. Python Linting & Formatting ---
  if py_files:
    print(f"[Python] Checking {len(py_files)} file(s)...")

    print('  -> Running pylint (-j 0)...')
    rc = f"--rcfile={REPO_ROOT / '.pylintrc'}"
    pylint_res = run_cmd(['pylint', '-j', '0', rc] + py_files)
    if pylint_res.returncode != 0:
      findings.append('Python pylint lint findings')

    if args.fix:
      print('  -> Running yapf formatting (-p -i)...')
      st = f"--style={REPO_ROOT / '.style.yapf'}"
      yapf_cmd = ['yapf', '-p', '-i', st] + py_files
    else:
      print('  -> Checking yapf formatting (-p -d)...')
      st = f"--style={REPO_ROOT / '.style.yapf'}"
      yapf_cmd = ['yapf', '-p', '-d', st] + py_files

    yapf_res = run_cmd(yapf_cmd)
    if yapf_res.returncode != 0:
      findings.append('Python yapf formatting findings')
  else:
    print('[Python] Skipped (no in-scope Python files changed)')

  # --- 2. Go Linting & Formatting ---
  if go_mods:
    print(f"[Go] Checking {len(go_mods)} module(s)...")

    for mod in go_mods:
      print(f"  -> Module: {mod}")
      mod_dir = REPO_ROOT / mod
      if args.fix:
        run_cmd(['gofmt', '-s', '-w', '.'], cwd=mod_dir)
        cmd = GOLANGCI_LINT_CMD + ['run', '--fix', './...']
      else:
        gofmt_res = run_cmd(['gofmt', '-s', '-d', '.'],
                            cwd=mod_dir,
                            capture_output=True)
        if gofmt_res.stdout.strip():
          print(gofmt_res.stdout)
          findings.append(f"Go format findings in {mod} (run with --fix)")
        cmd = GOLANGCI_LINT_CMD + ['run', './...']

      res = run_cmd(cmd, cwd=mod_dir)
      if res.returncode != 0:
        findings.append(f"Go lint findings in {mod}")
  else:
    print('[Go] Skipped (no in-scope Go modules changed)')

  # --- 3. Terraform Formatting ---
  if run_tf:
    print('[Terraform] Checking deployment/terraform/...')
    tf_dir = REPO_ROOT / 'deployment' / 'terraform'
    if args.fix:
      tf_res = run_cmd(['terraform', 'fmt', '-recursive'], cwd=tf_dir)
    else:
      tf_res = run_cmd(
          ['terraform', 'fmt', '-check', '-recursive', '-diff'],
          cwd=tf_dir,
      )

    if tf_res.returncode != 0:
      findings.append('Terraform format findings')
  else:
    print('[Terraform] Skipped (no Terraform files changed)')

  # --- Summary ---
  print('----------------------------------------------------')
  if findings:
    print('Findings detected! Please fix the above issues:')
    for finding in findings:
      print(f"  - {finding}")
    if not args.fix:
      print('Tip: Run with --fix (-f) to automatically format supported files.')
    return 1

  print('✓ All lint and format checks passed!')
  return 0


if __name__ == '__main__':
  sys.exit(main())
