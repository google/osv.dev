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

from urllib.parse import quote

PURL_ECOSYSTEMS = {
    'crates.io': 'cargo',
    'Debian': 'deb',
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


def _url_encode(package_name):
  """URL encode a PURL `namespace/name` or `name`."""
  parts = package_name.split('/')
  return '/'.join(quote(p) for p in parts)


def package_to_purl(ecosystem, package_name):
  """Convert a ecosystem and package name to PURL."""
  purl_type = PURL_ECOSYSTEMS.get(ecosystem)
  if not purl_type:
    return None

  suffix = ''

  if purl_type == 'maven':
    # PURLs use / to separate the group ID and the artifact ID.
    package_name = package_name.replace(':', '/', 1)

  if purl_type == 'deb':
    package_name = 'debian/' + package_name
    suffix = '?arch=source'

  return f'pkg:{purl_type}/{_url_encode(package_name)}{suffix}'
