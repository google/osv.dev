# Copyright 2023 Google LLC
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
"""Bioconductor helpers."""

import requests

from . import config
from .helper_base import Ecosystem, EnumerateError
from .. import semver_index


class Bioconductor(Ecosystem):
  """Bioconductor ecosystem helpers."""

  # Use the Posit Public Package Manager API to pull both the current and
  # older versions for a specific package since Bioconductor doesn't natively
  # support this functionality.
  _API_PACKAGE_URL_POSIT_BIOCONDUCTOR = \
    'https://packagemanager.posit.co/__api__/repos/4/packages/' + \
    '{package}?bioc_version={bioc_version}'
  _API_BIOC_VERSIONS_URL = 'https://packagemanager.posit.co/__api__/status'

  def get_bioc_versions(self):
    """
    get latest Bioconductor versions
    """
    response = requests.get(self._API_BIOC_VERSIONS_URL, timeout=60)
    data = response.json()
    if response.status_code == 404:
      raise RuntimeError('Failed to get Bioconductor versions')

    return [bioc['bioc_version'] for bioc in data['bioc_versions']]

  def sort_key(self, version):
    """Sort key."""
    return semver_index.parse(version)

  def _enumerate_versions(self,
                          url,
                          bioc_versions,
                          package,
                          introduced,
                          fixed=None,
                          last_affected=None,
                          limits=None):
    """Helper method to enumerate versions from a specific URL."""

    versions = []
    # Currently breaking on 3.19,
    # see https://github.com/google/osv.dev/pull/1477/files#r1575458933
    bioc_versions = bioc_versions.remove('3.19')
    for version in bioc_versions:
      response = requests.get(
          url.format(package=package, bioc_version=version),
          timeout=config.timeout)
      if response.status_code == 404:
        # Break here as we're starting at latest and going back
        # as packages won't disappear.
        break

      if response.status_code != 200:
        raise RuntimeError(
            f'Failed to get R versions for {package} with: {response.text}')

      response = response.json()
      if 'version' in response:
        versions += [response['version']]

    if len(versions) == 0:
      raise EnumerateError(f'Package {package} not found')

    self.sort_versions(versions)
    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    """Enumerate versions."""
    # Refresh to ensure any new Bioconductor versions are included
    bioc_versions = self.get_bioc_versions()
    versions = self._enumerate_versions(
        self._API_PACKAGE_URL_POSIT_BIOCONDUCTOR, bioc_versions, package,
        introduced, fixed, last_affected, limits)

    if versions is None:
      raise EnumerateError(f'Package {package} not found')

    return versions
