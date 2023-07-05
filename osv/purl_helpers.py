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
    'Alpine': 'apk',
    'crates.io': 'cargo',
    'Debian': 'deb',
    'Go': 'golang',
    'Hackage': 'hackage',
    'Hex': 'hex',
    'Maven': 'maven',
    'npm': 'npm',
    'NuGet': 'nuget',
    'OSS-Fuzz': 'generic',
    'Packagist': 'composer',
    'Pub': 'pub',
    'PyPI': 'pypi',
    'RubyGems': 'gem',
}


def _url_encode(package_name):
  """URL encode a PURL `namespace/name` or `name`."""
  parts = package_name.split('/')
  return '/'.join(quote(p) for p in parts)


def package_to_purl(ecosystem: str, package_name: str) -> str | None:
  """Convert a ecosystem and package name to PURL."""
  purl_type = PURL_ECOSYSTEMS.get(ecosystem)
  if not purl_type:
    return None

  suffix = ''

  if purl_type == 'maven':
    # PURLs use / to separate the group ID and the artifact ID.
    package_name = package_name.replace(':', '/', 1)

  if purl_type == 'deb' and ecosystem == 'Debian':
    package_name = 'debian/' + package_name
    suffix = '?arch=source'

  if purl_type == 'apk' and ecosystem == 'Alpine':
    package_name = 'alpine/' + package_name
    suffix = '?arch=source'

  return f'pkg:{purl_type}/{_url_encode(package_name)}{suffix}'


def purl_to_ecosystem(purl_type: str) -> str | None:
  """Convert purl to a specific ecosystem string"""
  ecosystem_purl = {v: k for k, v in PURL_ECOSYSTEMS.items()}
  return ecosystem_purl.get(purl_type)
