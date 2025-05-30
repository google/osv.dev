# Copyright 2024 Google LLC
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
"""Ecosystem helpers tests."""

import json
import re
import unittest
from typing import Any, Dict, KeysView

from . import _ecosystems


class EcosystemsTest(unittest.TestCase):
  """Ecosystem helpers tests."""
  schema_ecosystems: re.Pattern
  canonical_ecosystems: KeysView[str]

  def setUp(self) -> None:
    with open('osv/osv-schema/validation/schema.json') as schema_f:
      schema: Dict[str, Any] = json.load(schema_f)
    self.schema_ecosystems = re.compile(
        schema['$defs']['ecosystemWithSuffix']['pattern'])
    self.canonical_ecosystems = _ecosystems._ecosystems.keys()  # pylint: disable=protected-access

  def test_ecosystem_supported_by_schema(self) -> None:
    """Test ecosystems referenced exist in schema definition"""
    for ecosystem in self.canonical_ecosystems:
      self.assertIsNotNone(
          self.schema_ecosystems.match(ecosystem),
          msg=f'"{ecosystem}" not defined in schema')

    for ecosystem in _ecosystems.SEMVER_ECOSYSTEMS:
      self.assertIsNotNone(
          self.schema_ecosystems.match(ecosystem),
          msg=f'SEMVER ecosystem "{ecosystem}" not defined in schema')

    for ecosystem in _ecosystems.package_urls:
      self.assertIsNotNone(
          self.schema_ecosystems.match(ecosystem),
          msg=f'Purl "{ecosystem}" not defined in schema')

    for ecosystem in _ecosystems._OSV_TO_DEPS_ECOSYSTEMS_MAP:  # pylint: disable=protected-access
      self.assertIsNotNone(
          self.schema_ecosystems.match(ecosystem),
          msg=f'"{ecosystem}" in deps.dev map not defined in schema')


if __name__ == '__main__':
  unittest.main()
