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
"""Bioconductor ecosystem helper tests."""

import json
import unittest
from unittest import mock
import warnings
import vcr.unittest

from .. import ecosystems


class BioconductorEcosystemTest(vcr.unittest.VCRTestCase):
  """Bioconductor ecosystem helper tests."""

  def test_next_version(self):
    """Test next_version."""
    ecosystem = ecosystems.get('Bioconductor')
    with warnings.catch_warnings():
      # Filter the DeprecationWarning from next_version
      warnings.filterwarnings('ignore', 'Avoid using this method')
      self.assertEqual('1.18.0', ecosystem.next_version('a4', '1.16.0'))
      self.assertEqual('1.20.0', ecosystem.next_version('a4', '1.18.0'))
      with self.assertRaises(ecosystems.EnumerateError):
        ecosystem.next_version('doesnotexist123456', '1')

  def test_sort_key(self):
    """Test sort_key."""
    ecosystem = ecosystems.get('Bioconductor')
    self.assertGreater(
        ecosystem.sort_key('1.20.0'), ecosystem.sort_key('1.18.0'))
    self.assertLess(ecosystem.sort_key('1.18.0'), ecosystem.sort_key('1.18.1'))

    # Check the 0 sentinel value.
    self.assertLess(ecosystem.sort_key('0'), ecosystem.sort_key('0.0.0'))

    # Check >= / <= methods
    self.assertGreaterEqual(
        ecosystem.sort_key('1.20.0'), ecosystem.sort_key('1.18.0'))
    self.assertLessEqual(
        ecosystem.sort_key('1.18.0'), ecosystem.sort_key('1.20.0'))


def _http_response(status_code, text, payload=None):
  """Build a fake ``requests`` response for ``get_bioc_versions``."""
  response = mock.Mock()
  response.status_code = status_code
  response.text = text
  if payload is None:
    # Mimic requests' behaviour when the body is not valid JSON.
    response.json.side_effect = json.JSONDecodeError('Expecting value', text, 0)
  else:
    response.json.return_value = payload
  return response


class BioconductorGetBiocVersionsTest(unittest.TestCase):
  """Error handling for ``get_bioc_versions``."""

  def test_non_json_error_body_raises_runtime_error(self):
    """A non-JSON error page must not leak a bare JSONDecodeError.

    ``_enumerate_versions`` checks the status code before touching the
    body, so an HTML error page from the API is reported as a
    RuntimeError. ``get_bioc_versions`` must behave the same way.
    """
    ecosystem = ecosystems.get('Bioconductor')
    response = _http_response(502, '<html>502 Bad Gateway</html>')

    with mock.patch('requests.get', return_value=response):
      with self.assertRaises(RuntimeError) as ctx:
        ecosystem.get_bioc_versions()

    self.assertIn('Bioconductor', str(ctx.exception))
    self.assertIn('502 Bad Gateway', str(ctx.exception))

  def test_json_error_body_raises_runtime_error(self):
    """A JSON error payload must not be treated as a successful response."""
    ecosystem = ecosystems.get('Bioconductor')
    response = _http_response(
        500, '{"error": "internal"}', payload={'error': 'internal'})

    with mock.patch('requests.get', return_value=response):
      with self.assertRaises(RuntimeError) as ctx:
        ecosystem.get_bioc_versions()

    self.assertIn('Bioconductor', str(ctx.exception))

  def test_not_found_raises_runtime_error(self):
    """404 keeps raising the existing RuntimeError."""
    ecosystem = ecosystems.get('Bioconductor')
    response = _http_response(404, '{"error": "not found"}')

    with mock.patch('requests.get', return_value=response):
      with self.assertRaises(RuntimeError) as ctx:
        ecosystem.get_bioc_versions()

    self.assertIn('Bioconductor', str(ctx.exception))

  def test_success_returns_versions(self):
    """A 200 response still returns the Bioconductor versions."""
    ecosystem = ecosystems.get('Bioconductor')
    response = _http_response(
        200, '{"bioc_versions": [{"bioc_version": "3.18"}, '
        '{"bioc_version": "3.19"}]}',
        payload={
            'bioc_versions': [{
                'bioc_version': '3.18'
            }, {
                'bioc_version': '3.19'
            }]
        })

    with mock.patch('requests.get', return_value=response):
      self.assertEqual(['3.18', '3.19'], ecosystem.get_bioc_versions())

  def test_enumerate_versions_propagates_runtime_error(self):
    """``enumerate_versions`` surfaces the status-endpoint failure."""
    ecosystem = ecosystems.get('Bioconductor')
    response = _http_response(503, '<html>503 Service Unavailable</html>')

    with mock.patch('requests.get', return_value=response):
      with self.assertRaises(RuntimeError) as ctx:
        ecosystem.enumerate_versions('a4', '1.16.0')

    self.assertIn('503 Service Unavailable', str(ctx.exception))


if __name__ == '__main__':
  unittest.main()
