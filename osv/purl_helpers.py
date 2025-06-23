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

ParsedPURL = namedtuple('ParsedPURL', ['ecosystem', 'package', 'version'])
EcosystemPURL = namedtuple('EcosystemPURL', ['type', 'namespace'])

# PURL spec:
# https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst
ECOSYSTEM_PURL_DATA = {
    'AlmaLinux':
        EcosystemPURL('rpm', 'almalinux'),
    'Alpaquita':
        EcosystemPURL('apk', 'alpaquita'),
    'Alpine':
        EcosystemPURL('apk', 'alpine'),
    # Android
    'BellSoft Hardened Containers':
        EcosystemPURL('apk', 'bellsoft-hardened-containers'),
    # Bioconductor
    'Bitnami':
        EcosystemPURL('bitnami', None),
    'Chainguard':
        EcosystemPURL('apk', 'chainguard'),
    'ConanCenter':
        EcosystemPURL('conan', None),
    'CRAN':
        EcosystemPURL('cran', None),
    'crates.io':
        EcosystemPURL('cargo', None),
    'Debian':
        EcosystemPURL('deb', 'debian'),
    # GHC
    # GIT
    # GitHub Actions
    'Go':
        EcosystemPURL('golang', None),
    'Hackage':
        EcosystemPURL('hackage', None),
    'Hex':
        EcosystemPURL('hex', None),
    # Linux
    'Mageia':
        EcosystemPURL('rpm', 'mageia'),
    'Maven':
        EcosystemPURL('maven', None),
    'MinimOS':
        EcosystemPURL('apk', 'minimos'),
    'npm':
        EcosystemPURL('npm', None),
    'NuGet':
        EcosystemPURL('nuget', None),
    'openEuler':
        EcosystemPURL('rpm', 'openeuler'),
    'openSUSE':
        EcosystemPURL('rpm', 'opensuse'),
    'OSS-Fuzz':
        EcosystemPURL('generic', None),
    'Packagist':
        EcosystemPURL('composer', None),
    # Photon OS
    'Pub':
        EcosystemPURL('pub', None),
    'PyPI':
        EcosystemPURL('pypi', None),
    'Red Hat':
        EcosystemPURL('rpm', 'redhat'),
    'Rocky Linux':
        EcosystemPURL('rpm', 'rocky-linux'),
    'RubyGems':
        EcosystemPURL('gem', None),
    'SUSE':
        EcosystemPURL('rpm', 'suse'),
    'SwiftURL':
        EcosystemPURL('swift', None),
    'Ubuntu':
        EcosystemPURL('deb', 'ubuntu'),
    'Wolfi':
        EcosystemPURL('apk', 'wolfi'),
}

# Create the reverse lookup hash map
PURL_ECOSYSTEM_MAP = {
    purl_data: ecosystem
    for ecosystem, purl_data in ECOSYSTEM_PURL_DATA.items()
}


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
  if purl_namespace:
    purl_ecosystem = f'{purl_type}/{purl_namespace}'
  else:
    purl_ecosystem = purl_type

  suffix = ''

  if purl_type == 'maven':
    # PURLs use / to separate the group ID and the artifact ID.
    package_name = package_name.replace(':', '/', 1)

  if purl_type == 'deb' and ecosystem == 'Debian':
    suffix = '?arch=source'

  if purl_type == 'apk' and ecosystem in ('Alpine', 'Alpaquita',
                                          'BellSoft Hardened Containers'):
    suffix = '?arch=source'

  return f'pkg:{purl_ecosystem}/{_url_encode(package_name)}{suffix}'


def parse_purl(purl_str: str) -> ParsedPURL | None:
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

  # Find a matching ecosystem using both type and namespace.
  ecosystem = PURL_ECOSYSTEM_MAP.get(EcosystemPURL(purl.type, purl.namespace))
  if ecosystem:
    return ParsedPURL(ecosystem, package, version)

  # If no match is found, try again using only the type.
  # Some ecosystems may use the namespace to represent additional
  # information (like vendors) and the namespace might be optional.
  ecosystem = PURL_ECOSYSTEM_MAP.get(EcosystemPURL(purl.type, None))
  if not ecosystem:
    return None

  # For ecosystems with optional namespaces, the namespace might need to be
  # included as part of the package name.
  if purl.namespace:
    if purl.type == 'golang':
      package = purl.namespace + '/' + purl.name
      if purl.subpath:
        package = package + '/' + purl.subpath
    elif purl.type in ('composer', 'hex', 'npm', 'swift'):
      package = purl.namespace + '/' + purl.name
    elif purl.type == 'maven':
      package = purl.namespace + ':' + purl.name
    else:
      # Handle the case where the ecosystem shouldn't have a namespace.
      return None
  else:
    # Handle the case where the namespace is not supported.
    return None

  return ParsedPURL(ecosystem, package, version)
