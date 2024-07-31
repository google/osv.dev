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
"""Request helpers tests"""

import unittest
import types
from unittest import mock

from .request_helper import RequestHelper
from .cache import InMemoryCache


class RequestHelperTests(unittest.TestCase):
  """get_next_version tests."""

  @mock.patch('requests.sessions.Session.get')
  def test_cache(self, session_get: mock.MagicMock):
    """Test cache works as expected."""

    test_response = types.SimpleNamespace()
    test_response.status_code = 200
    test_response.text = 'test123'
    test_url = 'https://example.com'

    session_get.return_value = test_response

    cache = InMemoryCache()
    request_helper = RequestHelper(cache)

    example_result = request_helper.get(test_url)
    self.assertEqual(example_result, test_response.text)
    session_get.assert_called_once_with(test_url)

    cached_response = request_helper.get(test_url)
    self.assertEqual(example_result, cached_response)
    session_get.assert_called_once()  # Still only called once


if __name__ == '__main__':
  unittest.main()
