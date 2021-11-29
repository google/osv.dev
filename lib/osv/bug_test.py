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
"""Bug helper tests."""

import unittest

from . import bug


class NormalizeTest(unittest.TestCase):
  """Normalize tests."""

  def test_normalize(self):
    """Test version normalization."""
    tags = [
        '1.0',
        '22.3rc1',
        '1.2.3.4.5-rc1',
        '.1',
        '0.1.11.1',
        'project-123-1',
        'project-123-1RC',
        'project-123-1RC5',
        'arc-20200101',
        'php-8.0.0beta',
        'php-8.0.0beta4',
        'v6.0.0-alpha1',
        'android-10.0.0_r10',
    ]

    self.assertListEqual([
        '1-0',
        '22-3-rc1',
        '1-2-3-4-5-rc1',
        '1',
        '0-1-11-1',
        '123-1',
        '123-1-RC',
        '123-1-RC5',
        '20200101',
        '8-0-0-beta',
        '8-0-0-beta4',
        '6-0-0-alpha1',
        '10-0-0-10',
    ], bug.normalize_tags(tags))


if __name__ == '__main__':
  unittest.main()
