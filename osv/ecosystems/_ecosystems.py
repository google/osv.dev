# Copyright 2021 Google LLC
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

from osv.ecosystems.chainguard import Chainguard
from osv.ecosystems.wolfi import Wolfi
from .helper_base import Ecosystem, OrderingUnsupportedEcosystem
from .alma_linux import AlmaLinux
from .alpaquita import Alpaquita
from .alpine import Alpine
from .bioconductor import Bioconductor
from .cran import CRAN
from .debian import Debian
from .haskell import Hackage, GHC
from .mageia import Mageia
from .maven import Maven
from .minimos import MinimOS
from .nuget import NuGet
from .packagist import Packagist
from .pub import Pub
from .pypi import PyPI
from .rocky_linux import RockyLinux
from .redhat import RedHat
from .rubygems import RubyGems
from .semver_ecosystem_helper import SemverEcosystem
from .ubuntu import Ubuntu
from .suse import SUSE
from .opensuse import OpenSUSE

_ecosystems = {
    # SemVer-based ecosystems (remember keep synced with SEMVER_ECOSYSTEMS):
    'Bitnami': SemverEcosystem(),
    'crates.io': SemverEcosystem(),
    'Go': SemverEcosystem(),
    'Hex': SemverEcosystem(),
    'npm': SemverEcosystem(),
    'SwiftURL': SemverEcosystem(),
    # Non SemVer-based ecosystems
    'Bioconductor': Bioconductor(),
    'CRAN': CRAN(),
    'Chainguard': Chainguard(),
    'GHC': GHC(),
    'Hackage': Hackage(),
    'Maven': Maven(),
    'MinimOS': MinimOS(),
    'NuGet': NuGet(),
    'Drupal': Packagist(),
    'Packagist': Packagist(),
    'Pub': Pub(),
    'PyPI': PyPI(),
    'RubyGems': RubyGems(),
    'Wolfi': Wolfi(),
    # Ecosystems which require a release version for enumeration, which is
    # handled separately in get().
    # Ecosystems missing implementations:
    'Android': OrderingUnsupportedEcosystem(),
    'ConanCenter': OrderingUnsupportedEcosystem(),
    'GitHub Actions': OrderingUnsupportedEcosystem(),
    'Linux': OrderingUnsupportedEcosystem(),
    'OSS-Fuzz': OrderingUnsupportedEcosystem(),
    'Photon OS': OrderingUnsupportedEcosystem(),
    'GIT': OrderingUnsupportedEcosystem(),
}

# Semver-based ecosystems, should correspond to _ecosystems above.
# TODO(michaelkedar): Avoid need to keep in sync with above.
SEMVER_ECOSYSTEMS = {
    'Bitnami',
    'crates.io',
    'Go',
    'Hex',
    'npm',
    'SwiftURL',
}

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


def get(name: str) -> Ecosystem:
  """Get ecosystem helpers for a given ecosystem."""

  if name.startswith('Debian'):
    return Debian(name.partition(':')[2])

  if name.startswith('AlmaLinux'):
    return AlmaLinux()

  if name.startswith('Alpaquita'):
    return Alpaquita()

  if name.startswith('Alpine'):
    return Alpine(name.partition(':')[2])

  if name.startswith('BellSoft Hardened Containers'):
    return Alpaquita()

  if name.startswith('Mageia'):
    return Mageia()

  if name.startswith('Red Hat'):
    return RedHat()

  if name.startswith('Rocky Linux'):
    return RockyLinux()

  if name.startswith('Photon OS:'):
    # TODO(unassigned)
    return OrderingUnsupportedEcosystem()

  if name.startswith('Ubuntu'):
    return Ubuntu()

  if name.startswith('openSUSE'):
    return OpenSUSE()

  if name.startswith('SUSE'):
    return SUSE()

  return _ecosystems.get(normalize(name))


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


def map_ecosystem_to_deps_dev(ecosystem_name: str) -> str:
  return _OSV_TO_DEPS_ECOSYSTEMS_MAP.get(ecosystem_name)


def maybe_normalize_package_names(package_name: str, ecosystem: str) -> str:
  """Normalize package names as necessary."""
  if ecosystem == 'PyPI':
    # per https://peps.python.org/pep-0503/#normalized-names
    package_name = re.sub(r'[-_.]+', '-', package_name).lower()

  return package_name
