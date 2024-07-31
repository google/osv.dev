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
"""Analyze CLI tool."""

import argparse
import json
import logging
import os
import re
import subprocess

import yaml

# pylint: disable=relative-beyond-top-level
from .. import impact
from .. import sources


def main():
  logging.basicConfig(level=logging.INFO)
  parser = argparse.ArgumentParser(description='Analyze')
  parser.add_argument(
      '--analyze_git',
      help='Analyze git ranges',
      choices=['true', 'false'],
      default='true')
  parser.add_argument(
      '--detect_cherrypicks',
      help='Detect git cherry-picks (slow)',
      choices=['true', 'false'],
      default='false')
  parser.add_argument(
      '--format',
      help='Analyze git ranges',
      choices=['yaml', 'json'],
      default='yaml')
  parser.add_argument(
      '--key_path', help='Key path where vulnerability is stored', default='')
  parser.add_argument(
      '--checkout_path', help='Path for checking out repositories')
  parser.add_argument(
      '--pr_base', help='Pull request base branch (to diff against).')
  parser.add_argument(
      '--skip_pattern', help='Regex pattern to match skipped files.')
  parser.add_argument('paths', nargs='*', help='File paths')

  args = parser.parse_args()

  analyze_git = args.analyze_git == 'true'
  detect_cherrypicks = args.detect_cherrypicks == 'true'

  if args.pr_base:
    paths = subprocess.check_output(
        ['git', 'diff', '--name-only', args.pr_base]).decode().splitlines()
  else:
    paths = args.paths

  if not paths:
    print('No vulnerability paths specified.')

  for path in paths:
    if args.skip_pattern and re.search(args.skip_pattern, path):
      continue

    ext = os.path.splitext(path)[1]
    if args.format == 'yaml':
      if ext not in sources.YAML_EXTENSIONS:
        continue
    else:
      assert args.format == 'json'
      if ext not in sources.JSON_EXTENSIONS:
        continue

    if not os.path.exists(path):
      continue

    analyze(path, args.checkout_path, args.key_path, analyze_git,
            detect_cherrypicks)


def analyze(path, checkout_path, key_path, analyze_git, detect_cherrypicks):
  """Analyze and write changes to file."""
  logging.info('Analyzing %s', path)
  try:
    vuln = sources.parse_vulnerability(path, key_path)
  except Exception:
    logging.error('Failed to parse %s', path)
    return

  result = impact.analyze(
      vuln,
      analyze_git=analyze_git,
      checkout_path=checkout_path,
      detect_cherrypicks=detect_cherrypicks)
  if not result.has_changes:
    logging.info('No changes required.')
    return

  logging.info('Writing changes.')
  sources.write_vulnerability(vuln, path, key_path)
