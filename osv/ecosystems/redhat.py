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
"""Red Hat Linux ecosystem helper."""

from ..third_party.univers.rpm import RpmVersion
from .ecosystems_base import coarse_version_generic, OrderedEcosystem

# A real, valid Rpm Version to check against
_rpm_test_version = RpmVersion.from_string('0')


class RPM(OrderedEcosystem):
  """Red Hat Package Manager ecosystem helper."""

  def _sort_key(self, version):
    ver = RpmVersion.from_string(version)
    # Invalid RPM versions only reveal themselves when doing a comparison.
    try:
      _rpm_test_version < ver
    except Exception as e:
      raise ValueError(f'Invalid version: {version}') from e
    return ver

  def coarse_version(self, version: str) -> str:
    """Coarse version.

    Treats version as alternating digit/non-digit strings.
    Treats ~, ^, - as separators that sort before regular separators
    (e.g. 1.0~rc1 < 1.0).
    Epochs are preserved.
    """
    # Call sort key to validate the version
    self._sort_key(version)
    # Extract epoch, if it exists
    e, p, v = version.partition(':')
    if not p:
      v = e
      e = '0'
    try:
      epoch = int(e)
    except ValueError as e:
      raise ValueError(f'Invalid version: {version}') from e

    if epoch > 99:
      return '99:99999999.99999999.99999999'

    coarse = coarse_version_generic(
        v,
        # any non-alphanumeric character is considered a separator
        separators_regex=r'[^0-9A-Za-z~^-]',
        # ~, ^, - separators are special and treated as less than a regular
        # separator
        trim_regex=r'[~^-]',
        implicit_split=True,
        empty_as=None,
    )
    # Insert the epoch as we return
    return f'{epoch:02d}{coarse[2:]}'
