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
  parser.add_argument('paths', nargs='*', help='File paths')

  args = parser.parse_args()

  analyze_git = args.analyze_git == 'true'
  detect_cherrypicks = args.detect_cherrypicks == 'true'

  if args.pr_base:
    paths = subprocess.check_output(
        ['git', 'diff', '--name-only', args.pr_base]).decode().splitlines()
  else:
    paths = args.paths

  for path in paths:
    if not path.endswith(args.format):
      continue

    logging.info('Analyzing %s', path)
    analyze(path, args.checkout_path, args.format, args.key_path, analyze_git,
            detect_cherrypicks)


def analyze(path, checkout_path, file_format, key_path, analyze_git,
            detect_cherrypicks):
  """Analyze and write changes to file."""
  with open(path) as f:
    if file_format == 'json':
      data = json.load(f)
    else:
      # Validated by argument parsing.
      assert file_format == 'yaml'
      data = yaml.safe_load(f)

  vuln_data = data
  if key_path:
    try:
      for component in key_path.split('.'):
        vuln_data = vuln_data[component]
    except KeyError:
      logging.warning('Failed to parse %s with key path %s', path, key_path)
      return

  try:
    vuln = sources.parse_vulnerability_from_dict(vuln_data)
  except Exception:
    logging.warning('Failed to parse %s', path)
    return

  result = impact.analyze(
      vuln,
      analyze_git=analyze_git,
      checkout_path=checkout_path,
      detect_cherrypicks=detect_cherrypicks)
  if not result.has_changes:
    return

  # Update in place so `key_path` is automatically updated correctly.
  vuln_data.clear()
  vuln_data.update(sources.vulnerability_to_dict(vuln))

  with open(path, 'w') as f:
    if file_format == 'json':
      json.dump(data, f, indent=2)
    else:
      # Validated by argument parsing.
      assert file_format == 'yaml'
      yaml.dump(data, f, sort_keys=False, Dumper=sources.YamlDumper)
