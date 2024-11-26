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

from packageurl import PackageURL

PURL_ECOSYSTEMS = {
    'Alpine': 'apk',
    'Bitnami': 'bitnami',
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
    'SwiftURL': 'swift',
}

# PURL spec: scheme:type/namespace/name@version?qualifiers#subpath
# project ecosystems use purl.type to represent.
PURL_TYPE_ECOSYSTEMS = {
    # Android
    'bitnami': 'Bitnami',
    'cargo': 'crates.io',
    # CRAN
    'golang': 'Go',
    'hackage': 'Hackage',
    'hex': 'Hex',
    'maven': 'Maven',
    'npm': 'npm',
    'nuget': 'NuGet',
    'generic': 'OSS-Fuzz',
    'composer': 'Packagist',
    'pub': 'Pub',
    'pypi': 'PyPI',
    'gem': 'RubyGems',
    'swift': 'SwiftURL',
}

# PURL spec: scheme:type/namespace/name@version?qualifiers#subpath
# For Linux distributions, the namespace helps determine the ecosystem.
# This is because different distributions (like Red Hat and openSUSE)
# might use the same package manager (like RPM).
# Example:
#  - pkg:rpm/redhat/curl  ->  Ecosystem: redhat
#  - pkg:rpm/opensuse/curl ->  Ecosystem: opensuse
PURL_NAMESPACE_ECOSYSTEMS = {
    # AlmaLinux
    'alpine': 'Alpine',
    'chainguard': 'Chainguard',
    'debian': 'Debian',
    'opensuse': 'openSUSE',
    'redhat': 'Red Hat',
    'rocky-linux': 'Rocky Linux',
    'suse': 'SUSE',
    'ubuntu': 'Ubuntu',
    'wolfi': 'Wolfi',
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


def parse_purl_ecosystem(purl: PackageURL) -> str | None:
  """Extracts the ecosystem name from a PackageURL by checking
  its `type` and `namespace`."""
  return PURL_TYPE_ECOSYSTEMS.get(
      purl.type, PURL_NAMESPACE_ECOSYSTEMS.get(purl.namespace, None))
