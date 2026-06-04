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
"""sources tests."""

import json
import unittest

from . import sources


class ParseVulnerabilitiesFromDataTest(unittest.TestCase):
  """Tests for parse_vulnerabilities_from_data."""

  def test_malformed_json_includes_source_context(self):
    """A malformed JSON record names its source in the raised error."""
    source = 'gs://osv-test/CVE-2024-0001.json'
    with self.assertRaises(RuntimeError) as ctx:
      sources.parse_vulnerabilities_from_data(
          b'this is not json', '.json', source=source)

    # The raised error must identify which record failed.
    self.assertIn(source, str(ctx.exception))
    # The original decode error is preserved as the cause.
    self.assertIsInstance(ctx.exception.__cause__, json.JSONDecodeError)

  def test_malformed_yaml_includes_source_context(self):
    """A malformed YAML record names its source in the raised error."""
    source = 'gs://osv-test/CVE-2024-0002.yaml'
    with self.assertRaises(RuntimeError) as ctx:
      sources.parse_vulnerabilities_from_data(
          b'id: [unterminated', '.yaml', source=source)

    self.assertIn(source, str(ctx.exception))

  def test_malformed_json_without_source_is_unchanged(self):
    """Without a source the original parse error is raised unchanged."""
    with self.assertRaises(json.JSONDecodeError):
      sources.parse_vulnerabilities_from_data(b'this is not json', '.json')

  def test_unknown_extension_with_source_includes_context(self):
    """An unknown extension surfaces its source when one is provided."""
    source = 'gs://osv-test/record.txt'
    with self.assertRaises(RuntimeError) as ctx:
      sources.parse_vulnerabilities_from_data(b'data', '.txt', source=source)

    self.assertIn(source, str(ctx.exception))


if __name__ == '__main__':
  unittest.main()
