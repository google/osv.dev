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

from .helper_base import Ecosystem, OrderingUnsupportedEcosystem
from .alpine import Alpine
from .debian import Debian
from .haskell import Hackage, GHC
from .maven import Maven
from .nuget import NuGet
from .packagist import Packagist
from .pub import Pub
from .pypi import PyPI
from .cran import CRAN
from .bioconductor import Bioconductor
from .rubygems import RubyGems
from .semver_ecosystem_helper import SemverEcosystem

_ecosystems = {
    'Bioconductor': Bioconductor(),
    'CRAN': CRAN(),
    'GHC': GHC(),
    'Hackage': Hackage(),
    'Maven': Maven(),
    'NuGet': NuGet(),
    'Packagist': Packagist(),
    'Pub': Pub(),
    'PyPI': PyPI(),
    'RubyGems': RubyGems(),
    # SemVer-based ecosystems (remember keep synced with SEMVER_ECOSYSTEMS):
    'Bitnami': SemverEcosystem(),
    'crates.io': SemverEcosystem(),
    'Go': SemverEcosystem(),
    'Hex': SemverEcosystem(),
    'npm': SemverEcosystem(),
    'SwiftURL': SemverEcosystem(),
    # Ecosystems missing implementations:
    'Android': OrderingUnsupportedEcosystem(),
    'ConanCenter': OrderingUnsupportedEcosystem(),
    'GitHub Actions': OrderingUnsupportedEcosystem(),
    'Linux': OrderingUnsupportedEcosystem(),
    'OSS-Fuzz': OrderingUnsupportedEcosystem(),
    # Ecosystems which require a release version for enumeration, which is
    # handled separately in get().
    'AlmaLinux': OrderingUnsupportedEcosystem(),
    'Alpine': OrderingUnsupportedEcosystem(),
    'Chainguard': OrderingUnsupportedEcosystem(),
    'Debian': OrderingUnsupportedEcosystem(),
    'Photon OS': OrderingUnsupportedEcosystem(),
    'Rocky Linux': OrderingUnsupportedEcosystem(),
    'Ubuntu': OrderingUnsupportedEcosystem(),
    'Wolfi': OrderingUnsupportedEcosystem(),
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
    'npm': 'https://www.npmjs.com/package/',
    'NuGet': 'https://www.nuget.org/packages/',
    'Packagist': 'https://packagist.org/packages/',
    'Pub': 'https://pub.dev/packages/',
    'PyPI': 'https://pypi.org/project/',
    'Rocky Linux': 'https://pkgs.org/download/',
    'RubyGems': 'https://rubygems.org/gems/',
}


def get(name: str) -> Ecosystem:
  """Get ecosystem helpers for a given ecosystem."""

  if name.startswith('Debian:'):
    return Debian(name.split(':')[1])

  if name.startswith('Alpine:'):
    return Alpine(name.split(':')[1])

  if name.startswith('AlmaLinux:'):
    # TODO(unassigned)
    return OrderingUnsupportedEcosystem()

  if name.startswith('Rocky Linux:'):
    # TODO(unassigned)
    return OrderingUnsupportedEcosystem()

  if name.startswith('Photon OS:'):
    # TODO(unassigned)
    return OrderingUnsupportedEcosystem()

  if name.startswith('Ubuntu:'):
    # TODO(unassigned)
    return OrderingUnsupportedEcosystem()

  return _ecosystems.get(name)


def normalize(ecosystem_name: str):
  return ecosystem_name.split(':')[0]
