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

from collections import namedtuple
from urllib.parse import quote

from packageurl import PackageURL

# PURL spec:
# https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
ECOSYSTEM_PURL_DATA = {
    'AlmaLinux': ('rpm', 'almalinux'),
    'Alpine': ('apk', 'alpine'),
    # Android
    'Bitnami': ('bitnami', None),
    'Chainguard': ('apk', 'chainguard'),
    'CRAN': ('cran', None),
    'crates.io': ('cargo', None),
    'Debian': ('deb', 'debian'),
    # GIT
    'GitHub Actions': ('github', None),
    'Go': ('golang', None),
    'Hackage': ('hackage', None),
    'Hex': ('hex', None),
    # Linux
    'Maven': ('maven', None),
    'npm': ('npm', None),
    'NuGet': ('nuget', None),
    'openSUSE': ('rpm', 'opensuse'),
    'OSS-Fuzz': ('generic', None),
    'Packagist': ('composer', None),
    'Pub': ('pub', None),
    'PyPI': ('pypi', None),
    'Red Hat': ('rpm', 'redhat'),
    'Rocky Linux': ('rpm', 'rocky-linux'),
    'RubyGems': ('gem', None),
    'SUSE': ('rpm', 'suse'),
    'SwiftURL': ('swift', None),
    'Ubuntu': ('deb', 'ubuntu'),
    'Wolfi': ('apk', 'wolfi'),
}

# Create the reverse lookup hash map
PURL_ECOSYSTEM_MAP = {
    (purl_type, purl_namespace): ecosystem
    for ecosystem, (purl_type, purl_namespace) in ECOSYSTEM_PURL_DATA.items()
}

Purl = namedtuple('Purl', ['ecosystem', 'package', 'version'])


def _url_encode(package_name):
  """URL encode a PURL `namespace/name` or `name`."""
  parts = package_name.split('/')
  return '/'.join(quote(p) for p in parts)


def package_to_purl(ecosystem: str, package_name: str) -> str | None:
  """Convert a ecosystem and package name to PURL."""
  purl_data = ECOSYSTEM_PURL_DATA.get(ecosystem)
  if not purl_data:
    return None

  purl_type, purl_namespace = purl_data
  purl_ecosystem = purl_type
  if purl_namespace:
    purl_ecosystem = f'{purl_type}/{purl_namespace}'

  suffix = ''

  if purl_type == 'maven':
    # PURLs use / to separate the group ID and the artifact ID.
    package_name = package_name.replace(':', '/', 1)

  if purl_type == 'deb' and ecosystem == 'Debian':
    suffix = '?arch=source'

  if purl_type == 'apk' and ecosystem == 'Alpine':
    suffix = '?arch=source'

  return f'pkg:{purl_ecosystem}/{_url_encode(package_name)}{suffix}'


def parse_purl(purl_str: str) -> Purl | None:
  """Parses a PURL string and extracts
  ecosystem, package, and version information.

  Args:
    purl_str: The Package URL string to parse.

  Returns:
    A tuple containing the ecosystem, package,
    and version, or None if parsing fails.
  """

  purl = PackageURL.from_string(
      purl_str)  # May raise ValueError for invalid PURL strings

  package = purl.name
  version = purl.version

  ecosystem = PURL_ECOSYSTEM_MAP.get((purl.type, purl.namespace))
  if not ecosystem:
    # check for matching ecosystems without using the namespace (special cases)
    ecosystem = PURL_ECOSYSTEM_MAP.get((purl.type, None))
    if not ecosystem:
      raise ValueError('Invalid ecosystem.')
    # Handle special cases for package name construction
    if purl.type == 'golang' and purl.namespace:
      # Go uses the combined purl.namespace and purl.name for Go package names
      # Example:
      #   pkg:golang/github.com/cri-o/cri-o
      #   -> namespace: github.com/cri-o
      #   -> name: cri-o
      #   -> package name in OSV: github.com/cri-o/cri-o
      package = purl.namespace + '/' + purl.name
    elif purl.type in ('hex', 'npm', 'swift') and purl.namespace:
      package = purl.namespace + '/' + purl.name
    elif purl.type == 'maven' and purl.namespace:
      package = purl.namespace + ':' + purl.name
    elif purl.type == 'composer' and purl.namespace:
      package = purl.namespace + '/' + purl.name
    else:
      raise ValueError('Invalid ecosystem.')

  return Purl(ecosystem, package, version)
