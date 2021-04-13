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
import packaging.version

import requests


class Ecosystem:
  """Ecosystem helpers."""

  def sort_versions(self, versions):
    """Sort versions."""
    raise NotImplementedError

  def enumerate_versions(self, package, introduced, fixed):
    """Enumerate versions."""
    raise NotImplementedError


class PyPI(Ecosystem):
  """PyPI ecosystem helpers."""

  _API_PACKAGE_URL = 'https://pypi.org/pypi/{package}/json'

  def sort_versions(self, versions):
    """Sort versions."""
    versions.sort(key=packaging.version.parse)

  def enumerate_versions(self, package, introduced, fixed):
    """Enumerate versions."""
    response = requests.get(self._API_PACKAGE_URL.format(package=package))
    response = response.json()
    versions = list(response['releases'].keys())
    self.sort_versions(versions)

    parsed_versions = [packaging.version.parse(v) for v in versions]

    if introduced:
      introduced = packaging.version.parse(introduced)
      start_idx = bisect.bisect_left(parsed_versions, introduced)
    else:
      start_idx = 0

    if fixed:
      fixed = packaging.version.parse(fixed)
      end_idx = bisect.bisect_left(parsed_versions, fixed)
    else:
      end_idx = len(versions)

    return versions[start_idx:end_idx]


def get(name):
  """Get ecosystem helpers for a given ecosytem."""
  if name == 'PyPI':
    return PyPI()

  return None
