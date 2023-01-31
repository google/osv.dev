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
from .maven import Maven
from .nuget import NuGet
from .packagist import Packagist
from .pub import Pub
from .pypi import PyPI
from .rubygems import RubyGems
from .semver_ecosystem_helper import SemverEcosystem

_ecosystems = {
    'Maven': Maven(),
    'NuGet': NuGet(),
    'Packagist': Packagist(),
    'Pub': Pub(),
    'PyPI': PyPI(),
    'RubyGems': RubyGems(),
    # SemVer-based ecosystems (remember keep synced with SEMVER_ECOSYSTEMS):
    'crates.io': SemverEcosystem(),
    'Go': SemverEcosystem(),
    'Hex': SemverEcosystem(),
    'npm': SemverEcosystem(),
    # Ecosystems missing implementations:
    'Android': OrderingUnsupportedEcosystem(),
    'GitHub Actions': OrderingUnsupportedEcosystem(),
    'Linux': OrderingUnsupportedEcosystem(),
    'OSS-Fuzz': OrderingUnsupportedEcosystem(),
    # Alpine and Debian require a release version for enumeration, which is
    # handled separately in get().
    'Alpine': OrderingUnsupportedEcosystem(),
    'Debian': OrderingUnsupportedEcosystem(),
}

# Semver-based ecosystems, should correspond to _ecoystems above.
# TODO(michaelkedar): Avoid need to keep in sync with above.
SEMVER_ECOSYSTEMS = {
    'crates.io',
    'Go',
    'Hex',
    'npm',
}


def get(name: str) -> Ecosystem:
  """Get ecosystem helpers for a given ecosystem."""

  if name.startswith('Debian:'):
    return Debian(name.split(':')[1])

  if name.startswith('Alpine:'):
    return Alpine(name.split(':')[1])

  return _ecosystems.get(name)


def normalize(ecosystem_name: str):
  return ecosystem_name.split(':')[0]
