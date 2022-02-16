# Copyright 2022 Google LLC
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
"""PURL conversion utilities."""

PURL_ECOSYSTEMS = {
    'crates.io': 'cargo',
    'Hex': 'hex',
    'Go': 'golang',
    'Maven': 'maven',
    'NuGet': 'nuget',
    'npm': 'npm',
    'Packagist': 'composer',
    'OSS-Fuzz': 'generic',
    'PyPI': 'pypi',
    'RubyGems': 'gem',
}


def package_to_purl(ecosystem, package_name):
  """Convert a ecosystem and package name to PURL."""
  purl_type = PURL_ECOSYSTEMS.get(ecosystem)
  if not purl_type:
    return None

  if purl_type == 'maven':
    # PURLs use / to separate the group ID and the artifact ID.
    package_name = package_name.replace(':', '/', 1)

  return f'pkg:{purl_type}/{package_name}'
