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
"""Sitemap generator tests."""

# limitations under the License.
import unittest
import tempfile
from unittest.mock import patch, MagicMock
import generate_sitemap
import osv
from datetime import datetime
from datetime import UTC


class TestSitemapGeneration(unittest.TestCase):
  """Tests to verify the functionality of the sitemap generator script"""

  def temp_file(self):
    # Create a temporary file for testing
    self.test_file = tempfile.NamedTemporaryFile(delete=False)
    self.test_file.write(b'This is a test file.')
    self.test_file.close()
    return self.test_file.name

  @patch.object(osv.Bug, 'query')
  def test_fetch_vulnerabilities_and_dates(self, mock_query):
    """Test it returns the vulnerability ids for ecosystem"""
    # Mock the returned query
    mock_query.return_value.order.return_value = [
        MagicMock(
            last_modified=datetime.fromtimestamp(10, tz=UTC),
            key=MagicMock(id=MagicMock(return_value='vuln1'))),
        MagicMock(
            last_modified=datetime.fromtimestamp(20, tz=UTC),
            key=MagicMock(id=MagicMock(return_value='vuln2'))),
    ]

    result = generate_sitemap.fetch_vulnerabilities_and_dates('Go')
    self.assertEqual(result, [('vuln1', datetime.fromtimestamp(10, tz=UTC)),
                              ('vuln2', datetime.fromtimestamp(20, tz=UTC))])

  @patch.object(osv.Bug, 'query')
  def test_osv_get_ecosystems(self, mock_query):
    """Test it returns the ecosystems"""
    # Mock the returned query
    mock_query.return_value = [
        MagicMock(ecosystem=['UVI']),
        MagicMock(ecosystem=['Go'])
    ]

    result = generate_sitemap.osv_get_ecosystems()
    self.assertEqual(result, ['Go', 'UVI'])

  @patch('generate_sitemap.fetch_vulnerabilities_and_dates')
  @patch('generate_sitemap.ElementTree')
  def test_generate_sitemap_for_ecosystem(self, mock_element_tree,
                                          mock_fetch_vulns):
    """Check it generates the sitemap for ecosystem"""
    mock_fetch_vulns.return_value = [
        ('vuln1', datetime.fromtimestamp(10, tz=UTC)),
        ('vuln2', datetime.fromtimestamp(20, tz=UTC))
    ]
    mock_tree = MagicMock()
    mock_element_tree.return_value = mock_tree

    generate_sitemap.generate_sitemap_for_ecosystem('Go', 'http://example.com')

    mock_tree.write.assert_called_once_with(
        './sitemap_Go.xml', encoding='utf-8', xml_declaration=True)

  @patch('generate_sitemap.fetch_vulnerabilities_and_dates')
  @patch('generate_sitemap.ElementTree')
  def test_generate_sitemap_for_ecosystem_with_space(self, mock_element_tree,
                                                     mock_fetch_vulns):
    """"
    Check it creates the sitemap correctly where there is a space in the
    ecosystem name.
    """
    mock_fetch_vulns.return_value = [
        ('vuln1', datetime.fromtimestamp(10, tz=UTC)),
        ('vuln2', datetime.fromtimestamp(20, tz=UTC))
    ]
    mock_tree = MagicMock()
    mock_element_tree.return_value = mock_tree

    generate_sitemap.generate_sitemap_for_ecosystem('Rocky Linux',
                                                    'http://example.com')

    mock_tree.write.assert_called_once_with(
        './sitemap_Rocky_Linux.xml', encoding='utf-8', xml_declaration=True)

  @patch('generate_sitemap.fetch_vulnerabilities_and_dates')
  @patch('generate_sitemap.ElementTree')
  def test_generate_sitemap_for_ecosystem_with_period(self, mock_element_tree,
                                                      mock_fetch_vulns):
    """"
    Check it creates the sitemap correctly where there is a period in the
    ecosystem name.
    """
    mock_fetch_vulns.return_value = [
        ('vuln1', datetime.fromtimestamp(10, tz=UTC)),
        ('vuln2', datetime.fromtimestamp(20, tz=UTC))
    ]
    mock_tree = MagicMock()
    mock_element_tree.return_value = mock_tree

    generate_sitemap.generate_sitemap_for_ecosystem('crates.io',
                                                    'http://example.com')

    mock_tree.write.assert_called_once_with(
        './sitemap_crates__io.xml', encoding='utf-8', xml_declaration=True)

  @patch('generate_sitemap.ElementTree')
  def test_generate_sitemap_index(self, mock_element_tree):
    """Check it generates the sitemap index as expected"""
    mock_tree = MagicMock()
    mock_element_tree.return_value = mock_tree

    generate_sitemap.generate_sitemap_index(
        {'Go', 'UVI'}, 'http://example.com', {
            'Go': datetime.fromtimestamp(10, tz=UTC),
            'UVI': datetime.fromtimestamp(20, tz=UTC)
        })

    mock_tree.write.assert_called_once_with(
        './sitemap_index.xml', encoding='utf-8', xml_declaration=True)

  @patch('generate_sitemap.generate_sitemap_for_ecosystem')
  @patch('generate_sitemap.generate_sitemap_index')
  @patch('generate_sitemap.osv_get_ecosystems')
  def test_generate_sitemap(self, mock_get_ecosystems, mock_generate_index,
                            mock_generate_sitemap):
    """
    Check the outer wrapper generates the ecosystems' sitemaps as well as
    sitemap index.
    """
    mock_get_ecosystems.return_value = ['Go', 'UVI:Library', 'Android']
    mock_generate_sitemap.return_value = datetime.fromtimestamp(10, tz=UTC)
    generate_sitemap.generate_sitemaps('http://example.com')

    self.assertEqual(mock_generate_sitemap.call_count, 2)
    mock_generate_sitemap.assert_any_call('Go', 'http://example.com')
    mock_generate_sitemap.assert_any_call('Android', 'http://example.com')

    mock_generate_index.assert_called_once_with(
        {'Android', 'Go'}, 'http://example.com', {
            'Android': datetime.fromtimestamp(10, tz=UTC),
            'Go': datetime.fromtimestamp(10, tz=UTC),
        })


if __name__ == '__main__':
  unittest.main()
