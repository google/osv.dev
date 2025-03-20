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
"""CRAN helpers."""

import requests
import packaging_legacy.version

from . import config
from .helper_base import Ecosystem, EnumerateError


class CRAN(Ecosystem):
  """CRAN ecosystem helpers."""

  # Use the Posit Public Package Manager API to pull both the current
  # and archived versions for a specific package since CRAN doesn't
  # natively support this functionality.
  _API_PACKAGE_URL_POSIT_CRAN = 'https://packagemanager.posit.co/__api__/' + \
    'repos/2/packages/{package}'

  def sort_key(self, version):
    """Sort key."""
    # Some documentation on CRAN versioning and the R numeric_version method:
    # https://cran.r-project.org/doc/manuals/R-exts.html#The-DESCRIPTION-file
    # https://stat.ethz.ch/R-manual/R-devel/library/base/html/numeric_version.html
    # The packaging.version appears to work for the typical X.Y.Z and
    # X.Y-Z cases
    version = version.replace("-", ".")
    # version.parse() handles invalid versions by returning LegacyVersion()
    return packaging_legacy.version.parse(version)

  def _enumerate_versions(self,
                          url,
                          package,
                          introduced,
                          fixed=None,
                          last_affected=None,
                          limits=None):
    """Helper method to enumerate versions from a specific URL."""
    response = requests.get(url.format(package=package), timeout=config.timeout)
    if response.status_code == 404:
      return None

    if response.status_code != 200:
      raise RuntimeError(
          f'Failed to get R versions for {package} with: {response.text}')

    response = response.json()
    versions = []
    if 'version' in response:
      versions = [response['version']]
    if 'archived' in response:
      versions += [archived['version'] for archived in response['archived']]

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
    versions = self._enumerate_versions(self._API_PACKAGE_URL_POSIT_CRAN,
                                        package, introduced, fixed,
                                        last_affected, limits)

    if versions is None:
      raise EnumerateError(f'Package {package} not found')

    return versions
