# Copyright 2025 Google LLC
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
"""Ecosystem helpers."""

import re

from .ecosystems_base import EnumerableEcosystem, OrderedEcosystem
from .alpine import Alpine, APK
from .bioconductor import Bioconductor
from .cran import CRAN
from .debian import Debian, DPKG
from .haskell import Hackage, GHC
from .hex import Hex
from .maven import Maven
from .nuget import NuGet
from .packagist import Packagist
from .pub import Pub
from .pypi import PyPI
from .redhat import RPM
from .root import Root
from .rubygems import RubyGems
from .semver_ecosystem_helper import SemverEcosystem, SemverLike
from .ubuntu import Ubuntu

_ecosystems = {
    'AlmaLinux': RPM,
    'Alpaquita': APK,
    'Alpine': Alpine,
    'BellSoft Hardened Containers': APK,
    'Bioconductor': Bioconductor,
    'Bitnami': SemverEcosystem,
    'Chainguard': APK,
    'CRAN': CRAN,
    'crates.io': SemverEcosystem,
    'Debian': Debian,
    'Echo': DPKG,
    'GHC': GHC,
    'Go': SemverEcosystem,
    'Hackage': Hackage,
    'Hex': Hex,
    'Julia': SemverEcosystem,
    'Mageia': RPM,
    'Maven': Maven,
    'MinimOS': APK,
    'npm': SemverEcosystem,
    'NuGet': NuGet,
    'openEuler': RPM,
    'openSUSE': RPM,
    'Packagist': Packagist,
    'Pub': Pub,
    'PyPI': PyPI,
    'Red Hat': RPM,
    'Rocky Linux': RPM,
    'Root': Root,
    'RubyGems': RubyGems,
    'SUSE': RPM,
    'SwiftURL': SemverEcosystem,
    'Ubuntu': Ubuntu,
    'VSCode': SemverLike,
    'Wolfi': APK,

    # Ecosystems known in the schema, but without implementations.
    # Must be kept in sync with osv-schema.
    'Android': None,
    'ConanCenter': None,
    'GIT': None,
    'GitHub Actions': None,
    'Kubernetes': None,
    'Linux': None,
    'OSS-Fuzz': None,
    'Photon OS': None,
}


def is_semver(ecosystem: str) -> bool:
  """Returns whether an ecosystem uses 'SEMVER' range types"""
  return isinstance(get(ecosystem), SemverEcosystem)


def is_known(ecosystem: str) -> bool:
  """Returns whether an ecosystem is known to OSV
  (even if ordering is not supported)."""
  name, _, _ = ecosystem.partition(':')
  return name in _ecosystems


package_urls = {
    'Android': 'https://android.googlesource.com/',
    'CRAN': 'https://cran.r-project.org/web/packages/',
    'crates.io': 'https://crates.io/crates/',
    'Debian': 'https://packages.debian.org/src:',
    'GitHub Actions': 'https://github.com/marketplace/actions/',
    'Go': 'https://',
    'Hackage': 'https://hackage.haskell.org/package/',
    'Hex': 'https://hex.pm/packages/',
    'Mageia': 'https://madb.mageia.org/show?rpm=',
    'npm': 'https://www.npmjs.com/package/',
    'NuGet': 'https://www.nuget.org/packages/',
    'Packagist': 'https://packagist.org/packages/',
    'Pub': 'https://pub.dev/packages/',
    'PyPI': 'https://pypi.org/project/',
    'Rocky Linux': 'https://pkgs.org/download/',
    'RubyGems': 'https://rubygems.org/gems/',
}

_OSV_TO_DEPS_ECOSYSTEMS_MAP = {
    'npm': 'npm',
    'Go': 'go',
    'Maven': 'maven',
    'PyPI': 'pypi',
    'NuGet': 'nuget',
    'crates.io': 'cargo'
}


def get(name: str) -> OrderedEcosystem | EnumerableEcosystem | None:
  """Get ecosystem helpers for a given ecosystem."""
  name, _, suffix = name.partition(':')
  ecosys = _ecosystems.get(name)
  if ecosys is None:
    return None
  return ecosys(suffix)


def normalize(ecosystem_name: str):
  return ecosystem_name.split(':')[0]


def remove_variants(ecosystem_name: str) -> str | None:
  result = None
  # For Ubuntu, remove ":Pro" and ":LTS"
  if ecosystem_name.startswith('Ubuntu'):
    result = ecosystem_name.replace(':Pro', '').replace(':LTS', '')

  return result


def add_matching_ecosystems(original_set: set[str]) -> set[str]:
  """
  For Linux distributions, some release versions may have different variants.
  For example, Ubuntu:22.04 is equivalent to Ubuntu:22.04:LTS.
  This function adds all matching ecosystems
  to the datastore to facilitate API queries.

  For example:
  - "Ubuntu:Pro:18.04:LTS" would also be "Ubuntu:18.04"

  Args:
    original_set: The original ecosystem set

  Returns:
    A new set with the added matching ecosystems.
  """
  new_set = set(original_set)
  for ecosystem in original_set:
    # For Ubuntu, remove ":Pro" and ":LTS"
    new_ecosystem = remove_variants(ecosystem)
    if new_ecosystem:
      new_set.add(new_ecosystem)
  return new_set


def is_supported_in_deps_dev(ecosystem_name: str) -> bool:
  return ecosystem_name in _OSV_TO_DEPS_ECOSYSTEMS_MAP


def map_ecosystem_to_deps_dev(ecosystem_name: str) -> str | None:
  return _OSV_TO_DEPS_ECOSYSTEMS_MAP.get(ecosystem_name)


def maybe_normalize_package_names(package_name: str, ecosystem: str) -> str:
  """Normalize package names as necessary."""
  if ecosystem == 'PyPI':
    # per https://peps.python.org/pep-0503/#normalized-names
    package_name = re.sub(r'[-_.]+', '-', package_name).lower()

  return package_name
