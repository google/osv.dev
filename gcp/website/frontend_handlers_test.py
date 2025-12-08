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
"""Frontend handler tests."""
import shutil
import tempfile
import unittest

from google.cloud import ndb

import frontend_handlers
from osv import models
from osv import tests

emulator = None


class FrontendHandlerTest(unittest.TestCase):
  """Frontend handler tests."""

  def setUp(self):
    emulator.reset()
    self.maxDiff = None  # pylint: disable=invalid-name
    self.tmp_dir = tempfile.mkdtemp()

    tests.mock_datetime(self)

  def tearDown(self):
    shutil.rmtree(self.tmp_dir, ignore_errors=True)

  def test_ecosystem_counts(self):
    """Test ecosystem counts aggregates correctly updates."""
    models.Bug(
        id='OSV-0',
        db_id='OSV-0',
        status=1,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'PyPI',
                'name': 'blah',
            },
        }]).put()

    models.Bug(
        id='OSV-1',
        db_id='OSV-1',
        status=1,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:3.1',
                'name': 'blah',
            },
        }, {
            'package': {
                'ecosystem': 'Debian:7',
                'name': 'blah',
            },
        }]).put()

    models.Bug(
        id='OSV-2',
        db_id='OSV-2',
        status=1,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:8',
                'name': 'blah',
            },
        }]).put()

    # Invalid entries.
    models.Bug(
        id='OSV-3',
        db_id='OSV-3',
        status=2,
        public=True,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:8',
                'name': 'blah',
            },
        }]).put()

    models.Bug(
        id='OSV-4',
        db_id='OSV-4',
        status=1,
        public=False,
        source='test',
        affected_packages=[{
            'package': {
                'ecosystem': 'Debian:8',
                'name': 'blah',
            },
        }]).put()

    counts = frontend_handlers.osv_get_ecosystem_counts()
    self.assertDictEqual({'Debian': 2, 'PyPI': 1}, counts)


class MarkdownFilterTest(unittest.TestCase):
  """Tests for markdown template filter."""

  def test_removes_empty_anchor_tags(self):
    """Test removal of empty anchor tags."""
    result = frontend_handlers.markdown(
        'Text <a name="test"></a> <a name="foo"/> more')
    self.assertNotIn('name="test"', result)
    self.assertNotIn('name="foo"', result)
    self.assertIn('Text', result)

  def test_removes_anchor_with_multiple_attributes(self):
    """Test anchor tags with name and other attributes are removed."""
    result = frontend_handlers.markdown('<a name="x" id="y" class="z"></a>')
    self.assertNotIn('name="x"', result)

  def test_preserves_anchor_with_content(self):
    """Test anchor tags with content are preserved."""
    result = frontend_handlers.markdown('[Link](http://example.com)')
    self.assertIn('href', result)
    self.assertIn('Link', result)

  def test_sanitizes_urls_and_escapes_comments(self):
    """Test HTML comment escaping."""
    result = frontend_handlers.markdown('Text <!-- comment --> more')
    self.assertIn('&lt;!--', result)
    self.assertNotIn('<!--', result)

  def test_handles_empty_and_none(self):
    """Test empty string and None inputs."""
    self.assertEqual('', frontend_handlers.markdown(None))
    self.assertEqual('', frontend_handlers.markdown(''))

  def test_escapes_xss(self):
    """Test XSS attempts are escaped."""
    result = frontend_handlers.markdown('<script>alert(1)</script>')
    self.assertNotIn('<script>', result)
    self.assertIn('&lt;script&gt;', result)


def setUpModule():
  """Set up the test module."""
  # Start the emulator BEFORE creating the ndb client
  global emulator
  emulator = unittest.enterModuleContext(tests.datastore_emulator())
  unittest.enterModuleContext(ndb.Client().context(cache_policy=False))


if __name__ == '__main__':
  unittest.main()
