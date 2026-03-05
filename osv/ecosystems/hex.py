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
"""Hex ecosystem helper."""

import json

from . import config
from .ecosystems_base import EnumerableEcosystem, EnumerateError
from .semver_ecosystem_helper import SemverEcosystem
from ..request_helper import RequestError, RequestHelper


class Hex(EnumerableEcosystem, SemverEcosystem):
  """Hex ecosystem"""

  _API_PACKAGE_URL = 'https://hex.pm/api/packages/{package}'

  def enumerate_versions(self,
                         package,
                         introduced,
                         fixed=None,
                         last_affected=None,
                         limits=None):
    url = self._API_PACKAGE_URL.format(package=package.lower())
    request_helper = RequestHelper(config.shared_cache)
    try:
      text_response = request_helper.get(url)
    except RequestError as ex:
      if ex.response.status_code == 404:
        raise EnumerateError(f'Package {package} not found') from ex
      raise RuntimeError('Failed to get Hex versions for '
                         f'{package} with: {ex.response.text}') from ex

    response = json.loads(text_response)
    versions: list[str] = [x['version'] for x in response['releases']]
    self.sort_versions(versions)

    return self._get_affected_versions(versions, introduced, fixed,
                                       last_affected, limits)
