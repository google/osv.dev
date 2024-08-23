# Copyright 2021 Google LLC
# Copyright 2023 Fraser Tweedale
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
"""
Haskell ecosystem helpers.

Contact the Haskell Security Response Team <security-advisories@haskell.org>
if something is broken and you need help to fix it.

"""

import requests
import typing

from . import config
from .helper_base import Ecosystem, EnumerateError
from .. import semver_index


class Hackage(Ecosystem):
  """Hackage (Haskell package index) ecosystem."""

  _API_PACKAGE_URL = 'https://hackage.haskell.org/package/{package}.json'

  def sort_key(self, version):
    """Sort key.

    The Haskell package version data type is defined at
    https://hackage.haskell.org/package/Cabal-syntax/docs/Distribution-Types-Version.html

    """
    # If version is not valid, it is most likely an invalid input version
    # then sort it to the last/largest element
    try:
      return [int(x) for x in version.split('.')]
    except ValueError:
      return [999999]

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    response = requests.get(
        self._API_PACKAGE_URL.format(package=package), timeout=config.timeout)
    if response.status_code == 404:
      raise EnumerateError(f'Package {package} not found')
    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get Hackage versions for {package} with: {response.text}')

    response = response.json()
    versions = list(response.keys())

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)


class GHC(Ecosystem):
  """Glasgow Haskell Compiler (GHC) ecosystem."""

  _API_PACKAGE_URL = ('https://gitlab.haskell.org'
                      '/api/v4/projects/3561/repository/tags?per_page=100')
  # 100 is the maximum per_page size according to GitLab docs:
  # https://docs.gitlab.com/ee/api/rest/index.html#offset-based-pagination
  """
  Historical versions do not have tags in the Git repo, so we hardcode the
  list.  See https://github.com/google/osv.dev/pull/1463 for discussion.
  """
  HISTORICAL_VERSIONS = [
    '0.29',
    '2.10',
    '3.02', '3.03',
    '4.02', '4.04', '4.06', '4.08', '4.08.1', '4.08.2',
    '5.00', '5.00.1', '5.00.2', '5.02', '5.02.1', '5.02.2', '5.02.3',
    '5.04', '5.04.1', '5.04.2', '5.04.3',
    '6.0', '6.0.1',
    '6.2', '6.2.1', '6.2.2',
    '6.4', '6.4.1', '6.4.2', '6.4.3',
    '6.6', '6.6.1',
    '6.8.1', '6.8.1', '6.8.3',
    '6.10.1', '6.10.2-rc1', '6.10.2', '6.10.3', '6.10.4-rc1', '6.10.4',
    '6.12.1-rc1', '6.12.1', '6.12.2-rc1', '6.12.2', '6.12.3-rc1', '6.12.3',
    '7.0.1-rc1', '7.0.1-rc2', '7.0.1', '7.0.2-rc1', '7.0.2-rc2', '7.0.2',
    '7.0.3', '7.0.4-rc1', '7.0.4',
  ]  # yapf: disable

  def sort_key(self, version):
    """Sort key."""
    return semver_index.parse(version)

  @classmethod
  def tag_to_version(cls, tag: str) -> typing.Optional[str]:
    """Convert a tag to a release version, or return None if invalid.

    GHC release tags follow the scheme:

    - ghc-<major>.<minor>.<patch>-alpha<n>
    - ghc-<major>.<minor>.<patch>-rc<n>
    - ghc-<major>.<minor>.<patch>-release

    """
    parts = tag.split('-')
    if len(parts) == 3 and parts[0] == 'ghc' \
        and cls.is_major_minor_patch(parts[1]):
      if parts[2].startswith('alpha') or parts[2].startswith('rc'):
        return '-'.join(parts[1:3])
      if parts[2] == 'release':
        return parts[1]
    return None

  @staticmethod
  def is_major_minor_patch(s: str) -> bool:
    """Check that string matches ``<int>.<int>.<int>``."""
    parts = s.split('.')
    return len(parts) == 3 and all(x.isdigit() for x in parts)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions.

    Different components of GHC are part of the same software release.
    So we ignore the package (component) name.

    """

    # Versions come from tags from the GitLab API, which are paginated.
    # https://docs.gitlab.com/ee/api/rest/index.html#pagination-link-header
    url = self._API_PACKAGE_URL
    versions = self.HISTORICAL_VERSIONS.copy()
    while url is not None:
      response = requests.get(url, timeout=config.timeout)
      if response.status_code == 404:
        raise EnumerateError(f'GHC tag list not found at {url}')
      if response.status_code != 200:
        raise RuntimeError(
            f'Failed to get GHC versions from: {url} with: {response.text}')

      versions.extend(self.tag_to_version(x['name']) for x in response.json())

      if 'next' not in response.links:
        break
      url = response.links['next'].get('url')

    versions = [v for v in versions if v is not None]

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)
