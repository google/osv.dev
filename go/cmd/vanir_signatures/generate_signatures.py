#!/usr/bin/env python3
# Copyright 2026 Google LLC
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
"""Helper script invoked by Go to generate Vanir signatures for a batch."""

import argparse
import json
import logging
import sys

from vanir import signature
from vanir import vulnerability_manager
from vanir.code_extractors import code_extractor_base


def generate_signatures_for_batch(vuln_dicts: list[dict],
                                  git_working_dir: str) -> dict:
  """Generates Vanir signatures; returns {vuln_id: {affected_idx: [sigs]}}."""
  if not vuln_dicts:
    return {}

  vuln_manager = vulnerability_manager.VulnerabilityManager(vuln_dicts)
  extractor_config = code_extractor_base.ExtractorConfig(
      git_working_dir=git_working_dir)
  vuln_manager.generate_signatures(extractor_config=extractor_config)

  results = {}
  for vuln in vuln_manager.vulnerabilities:
    affected_sigs = {}
    for idx, affected_entry in enumerate(vuln.affected):
      if not affected_entry.vanir_signatures:
        continue
      serialized_sigs = [
          sig.to_osv_dict(use_string_hashes=True) if isinstance(
              sig, signature.Signature) else sig
          for sig in affected_entry.vanir_signatures
      ]
      if serialized_sigs:
        affected_sigs[str(idx)] = serialized_sigs

    if affected_sigs:
      results[vuln.id] = affected_sigs

  return results


def main():
  logging.basicConfig(level=logging.INFO, stream=sys.stderr)
  parser = argparse.ArgumentParser(
      description='Generate Vanir signatures for a batch of OSV records.')
  parser.add_argument('--input', required=True, help='Path to input JSON file.')
  parser.add_argument(
      '--output', required=True, help='Path to output JSON file.')
  parser.add_argument(
      '--git-working-dir',
      required=True,
      help='Path to shared temporary directory for Git operations.')
  args = parser.parse_args()

  with open(args.input, 'r', encoding='utf-8') as f:
    vuln_dicts = json.load(f)

  results = {}
  try:
    results = generate_signatures_for_batch(vuln_dicts, args.git_working_dir)
  except Exception as e:  # pylint: disable=broad-exception-caught
    logging.exception('Failed to generate Vanir signatures for batch of %d: %s',
                      len(vuln_dicts), e)
    sys.exit(1)

  with open(args.output, 'w', encoding='utf-8') as f:
    json.dump(results, f)


if __name__ == '__main__':
  main()
