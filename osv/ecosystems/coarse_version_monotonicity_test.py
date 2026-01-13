# Copyright 2026 Google LLC
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
"""Coarse version monotonicity tests."""

import re
import unittest
from hypothesis import given, example, strategies as st
import packaging.version

from .. import ecosystems
from ..third_party.univers.gem import GemVersion

from . import alpine
from . import cran
from . import debian
from . import haskell
from . import maven
from . import nuget
from . import packagist
from . import pub
from . import pypi
from . import redhat
from . import rubygems
from . import semver_ecosystem_helper

# Strategies
# Matches standard Alpine versions like 1.2.3, optionally with suffixes
# like _rc1, _p2, and revision -r3.
apk_version_strategy = st.from_regex(
    r'^[0-9]+(\.[0-9]+)*(_rc[0-9]*|_p[0-9]*)*(-r[0-9]+)?$')

# Matches R versions: sequence of numbers separated by dots or dashes
# (e.g. 1.2-3).
cran_version_strategy = st.from_regex(r'^[0-9]+([.-][0-9]+)+$')

# Matches Debian versions: optional epoch, upstream version
# (alphanumerics/separators), optional debian revision.
dpkg_version_strategy = st.from_regex(
    r'^(\d+:)?\d([A-Za-z0-9\.\+\~\-]+|[A-Za-z0-9\.\+\~]+-[A-Za-z0-9\+\.\~]+)?$')

# Matches Haskell versions: dot-separated integers (e.g. 1.2.3).
hackage_version_strategy = st.from_regex(r'^[0-9]+(\.[0-9]+)*$')

# Matches Maven versions: flexible sequence of numbers or identifiers
# separated by dots or dashes.
maven_version_strategy = st.from_regex(r'^(([0-9]*|[A-Za-z+]*)[.-]?)*$')

# Matches NuGet versions: SemVer-like, optional 'v' prefix, 4th component,
# prerelease/build metadata.
nuget_version_strategy = st.from_regex(
    r'^v?[0-9]+(\.[0-9]+)?(\.[0-9]+)?(\.[0-9]+)?(-[0-9a-zA-z.-]*)?\+?[0-9a-zA-z.-]*$'
)

# Matches Packagist versions: 'v' prefix, flexible components separated by
# ., +, _, -.
packagist_version_strategy = st.from_regex(r'^v?(([0-9]*|[A-Za-z+]*)[.+_-]?)*$')

# Matches Pub versions: SemVer-like, optional 'v' prefix.
pub_version_strategy = st.from_regex(
    r'^v?[0-9]+(\.[0-9]+)?(\.[0-9]+)?(-[0-9a-zA-z.-]*)?\+?[0-9a-zA-z.-]*$')

# Uses standard packaging.version pattern.
pypi_strategy = st.one_of(
    st.text(),  # legacy version can be any string
    st.from_regex(
        re.compile(r'^' + packaging.version.VERSION_PATTERN + r'$',
                   re.IGNORECASE | re.VERBOSE | re.ASCII)))

# Matches RPM versions: optional epoch, alternating alphanumeric segments.
rpm_version_strategy = st.from_regex(
    re.compile(r'^([0-9]+:)?(([0-9]+|[A-Za-z]+)((?![0-9A-Za-z])[ -~])*)+$',
               re.ASCII))

# Uses standard GemVersion pattern.
rubygems_version_strategy = st.from_regex(r'^' + GemVersion.VERSION_PATTERN +
                                          r'$')

# Matches standard SemVer: major.minor.patch, optional 'v', prerelease/build.
# Note: OSV's SemVer implementation coerces partial versions
# (e.g. '1.0' -> '1.0.0').
semver_strategy = st.from_regex(
    r'^v?[0-9]+(\.[0-9]+)?(\.[0-9]+)?(-[0-9a-zA-z.-]*)?\+?[0-9a-zA-z.-]*$')


def check_coarse_version_monotonic(test_case: unittest.TestCase,
                                   ecosystem: ecosystems.OrderedEcosystem,
                                   v1_str: str, v2_str: str):
  """Test coarse_version monotonicity."""
  v1 = ecosystem.sort_key(v1_str)
  v2 = ecosystem.sort_key(v2_str)
  if v2 < v1:
    v1, v2 = v2, v1
    v1_str, v2_str = v2_str, v1_str

  if v1.is_invalid:
    test_case.assertRaises(ValueError, ecosystem.coarse_version, v1_str)
  if v2.is_invalid:
    test_case.assertRaises(ValueError, ecosystem.coarse_version, v2_str)

  if not v1.is_invalid and not v2.is_invalid:
    v1_coarse = ecosystem.coarse_version(v1_str)
    v2_coarse = ecosystem.coarse_version(v2_str)
    test_case.assertLessEqual(v1_coarse, v2_coarse)


class CoarseVersionMonotonicityTest(unittest.TestCase):
  """Coarse version monotonicity tests."""

  @given(apk_version_strategy, apk_version_strategy)
  @example('1.02', '1.1')
  @example('5.0.9', '5.06.7')
  def test_apk(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, alpine.APK(), v1_str, v2_str)

  @given(cran_version_strategy, cran_version_strategy)
  def test_cran(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, cran.CRAN(), v1_str, v2_str)

  @given(dpkg_version_strategy, dpkg_version_strategy)
  def test_dpkg(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, debian.DPKG(), v1_str, v2_str)

  @given(hackage_version_strategy, hackage_version_strategy)
  def test_hackage(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, haskell.Hackage(), v1_str, v2_str)

  @given(maven_version_strategy, maven_version_strategy)
  def test_maven(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, maven.Maven(), v1_str, v2_str)

  @given(nuget_version_strategy, nuget_version_strategy)
  def test_nuget(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, nuget.NuGet(), v1_str, v2_str)

  @given(packagist_version_strategy, packagist_version_strategy)
  def test_packagist(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, packagist.Packagist(), v1_str, v2_str)

  @given(pub_version_strategy, pub_version_strategy)
  def test_pub(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, pub.Pub(), v1_str, v2_str)

  @given(pypi_strategy, pypi_strategy)
  def test_pypi(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, pypi.PyPI(), v1_str, v2_str)

  @given(rpm_version_strategy, rpm_version_strategy)
  def test_rpm(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, redhat.RPM(), v1_str, v2_str)

  @given(rubygems_version_strategy, rubygems_version_strategy)
  def test_rubygems(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, rubygems.RubyGems(), v1_str, v2_str)

  @given(semver_strategy, semver_strategy)
  def test_semver(self, v1_str, v2_str):
    check_coarse_version_monotonic(self, semver_ecosystem_helper.SemverLike(),
                                   v1_str, v2_str)
