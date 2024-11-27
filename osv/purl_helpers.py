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

Purl = namedtuple('Purl', ['ecosystem', 'package', 'version'])


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


def parse_purl(purl_str: str) -> Purl | None:
  """Parses a PURL string and extracts
  ecosystem, package, and version information.

  Args:
    purl_str: The Package URL string to parse.

  Returns:
    A tuple containing the ecosystem, package,
    and version, or None if parsing fails.
  """

  try:
    purl = PackageURL.from_string(purl_str)
  except ValueError as e:  # Catch potential parsing errors
    raise e

  package = purl.name
  version = purl.version

  match purl:
    case PackageURL(type='bitnami'):
      ecosystem = 'Bitnami'
    case PackageURL(type='cargo'):
      ecosystem = 'crates.io'
    case PackageURL(type='golang', namespace=namespace, name=name):
      # Go uses the combined purl.namespace and purl.name for Go package names
      # Example:
      #   pkg:golang/github.com/cri-o/cri-o
      #   -> namespace: github.com/cri-o
      #   -> name: cri-o
      #   -> package name in OSV: github.com/cri-o/cri-o
      ecosystem = 'Go'
      package = namespace + '/' + name
    case PackageURL(type='hackage'):
      ecosystem = 'Hackage'
    case PackageURL(type='hex'):
      ecosystem = 'Hex'
    case PackageURL(type='maven'):
      ecosystem = 'Maven'
    case PackageURL(type='npm'):
      ecosystem = 'npm'
    case PackageURL(type='nuget'):
      ecosystem = 'NuGet'
    case PackageURL(type='generic'):
      ecosystem = 'OSS-Fuzz'
    case PackageURL(type='composer'):
      ecosystem = 'Packagist'
    case PackageURL(type='pub'):
      ecosystem = 'Pub'
    case PackageURL(type='pypi'):
      ecosystem = 'PyPI'
    case PackageURL(type='gem'):
      ecosystem = 'RubyGems'
    case PackageURL(type='swift'):
      ecosystem = 'SwiftURL'

    # Linux distributions
    case PackageURL(type='apk', namespace='alpine'):
      ecosystem = 'Alpine'
    case PackageURL(type='apk', namespace='chainguard'):
      ecosystem = 'Chainguard'
    case PackageURL(type='deb', namespace='debian'):
      ecosystem = 'Debian'
    case PackageURL(type='rpm', namespace='opensuse'):
      ecosystem = 'openSUSE'
    case PackageURL(type='rpm', namespace='redhat'):
      ecosystem = 'Red Hat'
    case PackageURL(type='rpm', namespace='rocky-linux'):
      ecosystem = 'Rocky Linux'
    case PackageURL(type='rpm', namespace='suse'):
      ecosystem = 'SUSE'
    case PackageURL(type='deb', namespace='ubuntu'):
      ecosystem = 'Ubuntu'
    case PackageURL(type='apk', namespace='wolfi'):
      ecosystem = 'Wolfi'

    case _:
      raise ValueError('Invalid ecosystem.')

  return Purl(ecosystem, package, version)
