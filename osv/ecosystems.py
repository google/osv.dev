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

import bisect
import glob
import json
import logging
import os.path
import subprocess
import typing
from abc import ABC, abstractmethod

import grpc
import packaging.version
import urllib.parse
import requests

from .third_party.univers.debian import Version as DebianVersion
from .third_party.univers.gem import GemVersion
from .third_party.univers.alpine import AlpineLinuxVersion

from . import debian_version_cache
from . import deps_dev_pb2
from . import deps_dev_pb2_grpc
from . import repos
from . import maven
from . import nuget
from . import packagist_version
from . import semver_index
from .cache import Cache
from .cache import cached
from .request_helper import RequestError, RequestHelper

TIMEOUT = 30  # Timeout for HTTP(S) requests
use_deps_dev = False
deps_dev_api_key = ''
# Used for checking out git repositories
# Intended to be set in worker.py
work_dir: typing.Optional[str] = None

shared_cache: typing.Optional[Cache] = None


class EnumerateError(Exception):
  """Non-retryable version enumeration error."""


class Ecosystem(ABC):
  """Ecosystem helpers."""

  @property
  def name(self):
    """Get the name of the ecosystem."""
    return self.__class__.__name__

  def _before_limits(self, version, limits):
    """Return whether the given version is before any limits."""
    if not limits or '*' in limits:
      return True

    return any(
        self.sort_key(version) < self.sort_key(limit) for limit in limits)

  def next_version(self, package, version):
    """Get the next version after the given version."""
    versions = self.enumerate_versions(package, version, fixed=None)
    # Check if the key used for sorting is equal as sometimes different
    # strings could evaluate to the same version.
    if versions and self.sort_key(versions[0]) != self.sort_key(version):
      # Version does not exist, so use the first one that would sort
      # after it (which is what enumerate_versions returns).
      return versions[0]

    if len(versions) > 1:
      return versions[1]

    return None

  @abstractmethod
  def sort_key(self, version):
    """Sort key."""

  def sort_versions(self, versions):
    """Sort versions."""
    versions.sort(key=self.sort_key)

  @abstractmethod
  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""

  def _get_affected_versions(self, versions, introduced, fixed, last_affected,
                             limits):
    """Get affected versions.

    Args:
      versions: a list of version strings.
      introduced: a version string.
      fixed: a version string.
      last_affected: a version string.
      limits: a version string.

    Returns:
      A list of affected version strings.
    """
    parsed_versions = [self.sort_key(v) for v in versions]

    if introduced == '0':
      introduced = None

    if introduced:
      introduced = self.sort_key(introduced)
      start_idx = bisect.bisect_left(parsed_versions, introduced)
    else:
      start_idx = 0

    if fixed:
      fixed = self.sort_key(fixed)
      end_idx = bisect.bisect_left(parsed_versions, fixed)
    elif last_affected:
      last_affected = self.sort_key(last_affected)
      end_idx = bisect.bisect_right(parsed_versions, last_affected)
    else:
      end_idx = len(versions)

    affected = versions[start_idx:end_idx]
    return [v for v in affected if self._before_limits(v, limits)]

  @property
  def is_semver(self):
    return False

  @property
  def supports_ordering(self):
    return True


class OrderingUnsupportedEcosystem(Ecosystem):
  """Placeholder ecosystem helper for unimplemented ecosystems."""

  def sort_key(self, version):
    raise NotImplementedError('Ecosystem helper does not support sorting')

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    raise NotImplementedError('Ecosystem helper does not support enumeration')

  @property
  def supports_ordering(self):
    return False


class DepsDevMixin(Ecosystem, ABC):
  """deps.dev mixin."""

  _DEPS_DEV_ECOSYSTEM_MAP = {
      'Maven': deps_dev_pb2.System.SYSTEM_MAVEN,
      'PyPI': deps_dev_pb2.System.SYSTEM_PYPI,
  }

  def _deps_dev_enumerate(self,
                          package,
                          introduced,
                          fixed=None,
                          last_affected=None,
                          limits=None):
    """Use deps.dev to get list of versions."""
    versions = []
    ecosystem = self._DEPS_DEV_ECOSYSTEM_MAP[self.name]
    with grpc.secure_channel('api.deps.dev:443',
                             grpc.ssl_channel_credentials()) as channel:
      stub = deps_dev_pb2_grpc.InsightsStub(channel)
      try:
        stream = stub.Versions(
            deps_dev_pb2.VersionsRequest(
                package_key=deps_dev_pb2.PackageKey(
                    name=package, system=ecosystem)),
            metadata=(('x-depsdev-apikey', deps_dev_api_key),))

        for response in stream:
          versions.extend([v.version_key.version for v in response.versions])
      except grpc.RpcError as ex:
        if ex.code() == grpc.StatusCode.NOT_FOUND:
          raise EnumerateError(f'Package {package} not found') from ex

        raise RuntimeError(
            f'Failed to get {ecosystem} versions for {package} with: '
            f'{ex.details()}') from ex

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class SemverEcosystem(Ecosystem):
  """Generic semver ecosystem helpers."""

  def sort_key(self, version):
    """Sort key."""
    return semver_index.parse(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions (no-op)."""
    del package
    del introduced
    del fixed
    del limits

  def next_version(self, package, version):
    """Get the next version after the given version."""
    del package  # Unused.
    parsed_version = semver_index.parse(version)
    if parsed_version.prerelease:
      return version + '.0'

    return str(parsed_version.bump_patch()) + '-0'

  @property
  def is_semver(self):
    return True


Crates = SemverEcosystem
Go = SemverEcosystem
NPM = SemverEcosystem
Hex = SemverEcosystem


class PyPI(Ecosystem):
  """PyPI ecosystem helpers."""

  _API_PACKAGE_URL = 'https://pypi.org/pypi/{package}/json'

  def sort_key(self, version):
    """Sort key."""
    return packaging.version.parse(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    response = requests.get(
        self._API_PACKAGE_URL.format(package=package), timeout=TIMEOUT)

    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get PyPI versions for {package} with: {response.text}')

    response = response.json()
    versions = list(response['releases'].keys())
    self.sort_versions(versions)

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class Maven(DepsDevMixin):
  """Maven ecosystem."""

  _API_PACKAGE_URL = 'https://search.maven.org/solrsearch/select'

  def sort_key(self, version):
    """Sort key."""
    return maven.Version.from_string(version)

  @staticmethod
  def _get_versions(package):
    """Get versions."""
    versions = []
    request_helper = RequestHelper()

    group_id, artifact_id = package.split(':', 2)
    start = 0

    while True:
      query = {
          'q': f'g:"{group_id}" AND a:"{artifact_id}"',
          'core': 'gav',
          'rows': '20',
          'wt': 'json',
          'start': start
      }
      url = Maven._API_PACKAGE_URL + '?' + urllib.parse.urlencode(query)
      response = request_helper.get(url)
      response = json.loads(response)['response']
      if response['numFound'] == 0:
        raise EnumerateError(f'Package {package} not found')

      for result in response['docs']:
        versions.append(result['v'])

      if len(versions) >= response['numFound']:
        break

      start = len(versions)

    return versions

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    if use_deps_dev:
      return self._deps_dev_enumerate(package, introduced, fixed, limits=limits)

    get_versions = self._get_versions
    if shared_cache:
      get_versions = cached(shared_cache)(get_versions)

    versions = get_versions(package)
    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class RubyGems(Ecosystem):
  """RubyGems ecosystem."""

  _API_PACKAGE_URL = 'https://rubygems.org/api/v1/versions/{package}.json'

  def sort_key(self, version):
    """Sort key."""
    return GemVersion(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    response = requests.get(
        self._API_PACKAGE_URL.format(package=package), timeout=TIMEOUT)
    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get RubyGems versions for {package} with: {response.text}'
      )

    response = response.json()
    versions = [entry['number'] for entry in response]

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class NuGet(Ecosystem):
  """NuGet ecosystem."""

  _API_PACKAGE_URL = ('https://api.nuget.org/v3/registration5-semver1/'
                      '{package}/index.json')

  def sort_key(self, version):
    """Sort key."""
    return nuget.Version.from_string(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    url = self._API_PACKAGE_URL.format(package=package.lower())
    response = requests.get(url, timeout=TIMEOUT)
    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get NuGet versions for {package} with: {response.text}')

    response = response.json()

    versions = []
    for page in response['items']:
      if 'items' in page:
        items = page['items']
      else:
        items_response = requests.get(page['@id'], timeout=TIMEOUT)
        if items_response.status_code != 200:
          raise RuntimeError(
              f'Failed to get NuGet versions page for {package} with: '
              f'{response.text}')

        items = items_response.json()['items']

      for item in items:
        versions.append(item['catalogEntry']['version'])

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class Alpine(Ecosystem):
  """Alpine packages ecosystem"""

  _APORTS_GIT_URL = 'https://gitlab.alpinelinux.org/alpine/aports.git'
  _BRANCH_SUFFIX = '-stable'
  alpine_release_ver: str
  _GIT_REPO_PATH = 'version_enum/aports/'
  # Sometimes (2 or 3 packages) APKBUILD files are a bash script and version
  # is actually stored in variables. _kver is the common variable name.
  _PKGVER_ALIASES = ('+pkgver=', '+_kver=')
  _PKGREL_ALIASES = ('+pkgrel=', '+_krel=')

  def __init__(self, alpine_release_ver: str):
    self.alpine_release_ver = alpine_release_ver

  def get_branch_name(self) -> str:
    return self.alpine_release_ver.lstrip('v') + self._BRANCH_SUFFIX

  def sort_key(self, version):
    return AlpineLinuxVersion(version)

  @staticmethod
  def _process_git_log(output: str) -> list:
    """Takes git log diff output,
    finds all changes to pkgver and outputs that in an unsorted list
    """
    all_versions = set()
    lines = [
        x for x in output.splitlines()
        if len(x) == 0 or x.startswith(Alpine._PKGVER_ALIASES) or
        x.startswith(Alpine._PKGREL_ALIASES)
    ]
    # Reverse so that it's in chronological order.
    # The following loop also expects this order.
    lines.reverse()

    current_ver = None
    current_rel = None

    def clean_versions(ver: str) -> str:
      ver = ver.split(' #')[0]  # Remove comment lines
      ver = ver.strip(' "\'')  # Remove (occasional) quotes
      ver = ver.removeprefix('r')
      return ver

    for line in lines:
      if not line:
        if not current_ver or not current_rel:
          continue

        current_ver = clean_versions(current_ver)
        current_rel = clean_versions(current_rel)
        # Ignore occasional version that is still not valid.
        if AlpineLinuxVersion.is_valid(current_ver) and current_rel.isdigit():
          all_versions.add(current_ver + '-r' + current_rel)
        else:
          logging.warning('Alpine version "%s" - "%s" is not valid',
                          current_ver, current_rel)
        continue

      x_split = line.split('=', 1)
      if len(x_split) != 2:
        # Skip the occasional invalid versions
        continue

      num = x_split[1]
      if line.startswith(Alpine._PKGVER_ALIASES):
        current_ver = num
        continue

      if line.startswith(Alpine._PKGREL_ALIASES):
        current_rel = num
        continue

    # Return unsorted list of versions
    return list(all_versions)

  def enumerate_versions(self,
                         package: str,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    if work_dir is None:
      logging.error(
          "Tried to enumerate alpine version without workdir being set")
      return []

    get_versions = self._get_versions
    if shared_cache:
      get_versions = cached(shared_cache)(get_versions)

    versions = get_versions(self.get_branch_name(), package)
    self.sort_versions(versions)

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

  @staticmethod
  def _get_versions(branch: str, package: str) -> typing.List[str]:
    """Get all versions for a package from aports repo"""
    checkout_dir = os.path.join(work_dir, Alpine._GIT_REPO_PATH)
    repos.ensure_updated_checkout(
        Alpine._APORTS_GIT_URL, checkout_dir, branch=branch)
    directories = glob.glob(
        os.path.join(checkout_dir, '*', package.lower(), 'APKBUILD'),
        recursive=True)

    if len(directories) != 1:
      raise EnumerateError('Cannot find package in aports')

    relative_path = os.path.relpath(directories[0], checkout_dir)

    regex_test = '\\|'.join([
        '\\(' + x.removeprefix('+') + '\\)'
        for x in Alpine._PKGVER_ALIASES + Alpine._PKGREL_ALIASES
    ])

    stdout_data = subprocess.check_output([
        'git', 'log', '--oneline', '-L',
        '/' + regex_test + '/,+1:' + relative_path
    ],
                                          cwd=checkout_dir).decode('utf-8')

    versions = Alpine._process_git_log(stdout_data)
    return versions


class Debian(Ecosystem):
  """Debian ecosystem"""

  _API_PACKAGE_URL = 'https://snapshot.debian.org/mr/package/{package}/'
  debian_release_ver: str

  def __init__(self, debian_release_ver: str):
    self.debian_release_ver = debian_release_ver

  def sort_key(self, version):
    if not DebianVersion.is_valid(version):
      # If debian version is not valid, it is most likely an invalid fixed
      # version then sort it to the last/largest element
      return DebianVersion(999999, 999999)
    return DebianVersion.from_string(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    url = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper = RequestHelper(shared_cache)
    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError('Failed to get Debian versions for '
                         f'{package} with: {ex.response.text}') from ex

    response = json.loads(text_response)
    raw_versions: list[str] = [x['version'] for x in response['result']]

    # Remove rare cases of unknown versions
    def version_is_valid(v):
      if not DebianVersion.is_valid(v):
        logging.warning('Package %s has invalid version: %s', package, v)
        return False

      return True

    versions = [v for v in raw_versions if version_is_valid(v)]
    # Sort to ensure it is in the correct order
    self.sort_versions(versions)
    # The only versions with +deb
    versions = [
        x for x in versions
        if '+deb' not in x or f'+deb{self.debian_release_ver}' in x
    ]

    if introduced == '0':
      # Update introduced to the first version of the debian version
      introduced = debian_version_cache.get_first_package_version(
          package, self.debian_release_ver)

    if fixed is not None and not DebianVersion.is_valid(fixed):
      logging.warning(
          'Package %s has invalid fixed version: %s. In debian release %s',
          package, fixed, self.debian_release_ver)
      return []

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class Packagist(Ecosystem):
  """Packagist ecosystem"""

  _API_PACKAGE_URL = 'https://repo.packagist.org/p2/{package}.json'

  def sort_key(self, version):
    return packagist_version.PackagistVersion(version)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    url = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper = RequestHelper(shared_cache)
    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError('Failed to get Packagist versions for '
                         f'{package} with: {ex.response.text}') from ex

    response = json.loads(text_response)
    versions: list[str] = [x['version'] for x in response['packages'][package]]
    self.sort_versions(versions)
    # TODO(rexpan): Potentially filter out branch versions like dev-master

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


_ecosystems = {
    'crates.io': Crates(),
    'Go': Go(),
    'Hex': Hex(),
    'Maven': Maven(),
    'npm': NPM(),
    'NuGet': NuGet(),
    'Packagist': Packagist(),
    'PyPI': PyPI(),
    'RubyGems': RubyGems(),
    # Ecosystems missing implementations:
    'Android': OrderingUnsupportedEcosystem(),
    'GitHub Actions': OrderingUnsupportedEcosystem(),
    'Linux': OrderingUnsupportedEcosystem(),
    'OSS-Fuzz': OrderingUnsupportedEcosystem(),
    'Pub': OrderingUnsupportedEcosystem(),
    # Alpine and Debian require a release version for enumeration, which is
    # handled separately in get().
    'Alpine': OrderingUnsupportedEcosystem(),
    'Debian': OrderingUnsupportedEcosystem(),
}

SEMVER_ECOSYSTEMS = {
    'crates.io',
    'Go',
    'npm',
    'Hex',
}


def get(name: str) -> Ecosystem:
  """Get ecosystem helpers for a given ecosystem."""

  if name.startswith('Debian:'):
    return Debian(name.split(':')[1])

  if name.startswith('Alpine:'):
    return Alpine(name.split(':')[1])

  return _ecosystems.get(name)


def set_cache(cache: typing.Optional[Cache]):
  """Configures and enables the redis caching layer"""
  global shared_cache
  shared_cache = cache


def normalize(ecosystem_name: str):
  return ecosystem_name.split(':')[0]
