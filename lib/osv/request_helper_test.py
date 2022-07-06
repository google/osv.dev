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

import os
import unittest
import types
from unittest import mock

import requests

from .request_helper import RequestHelper
from .cache import InMemoryCache


class RequestHelperTests(unittest.TestCase):
  """get_next_version tests."""

  @mock.patch('requests.sessions.Session.get')
  def test_cache(self, session_get: mock.MagicMock):

    TEST_RESPONSE = types.SimpleNamespace()
    TEST_RESPONSE.status_code = 200
    TEST_RESPONSE.text = 'test123'
    TEST_URL = "https://example.com"

    session_get.return_value = TEST_RESPONSE

    cache = InMemoryCache()
    request_helper = RequestHelper(cache)

    example_result = request_helper.get(TEST_URL)
    self.assertEqual(example_result, TEST_RESPONSE.text)
    session_get.assert_called_once_with(TEST_URL)

    cached_response = request_helper.get(TEST_URL)
    self.assertEqual(example_result, cached_response)
    session_get.assert_called_once() # Still only called once


if __name__ == '__main__':
  unittest.main()
