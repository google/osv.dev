"""Tests for the crates.io ecosystem helper."""

import json
import unittest
from unittest import mock

from .crates import CratesIO


def _mock_versions_payload() -> str:
  """Create a mocked crates.io API payload."""

  payload = {
      'versions': [
          {
              'num': '0.16.2+1.7.2',
              'yanked': False,
          },
          {
              'num': '0.16.1+1.6.4',
              'yanked': False,
          },
          {
              'num': '0.16.1+1.6.4-alpha',
              'yanked': True,
          },
          {
              'num': '0.15.0',
              'yanked': False,
          },
      ],
  }
  return json.dumps(payload)


class CratesIOTest(unittest.TestCase):
  """Unit tests for CratesIO."""

  def setUp(self):
    self.helper = CratesIO()

  @mock.patch('osv.ecosystems.crates.RequestHelper.get')
  def test_enumerate_versions(self, mock_get):
    mock_get.return_value = _mock_versions_payload()

    versions = self.helper.enumerate_versions(
        'libgit2-sys', introduced='0.0.0-0', fixed='0.16.2')

    self.assertIn('0.16.1+1.6.4', versions)
    self.assertIn('0.15.0', versions)
    self.assertNotIn('0.16.2+1.7.2', versions)

  @mock.patch('osv.ecosystems.crates.RequestHelper.get')
  def test_resolve_version_adds_metadata(self, mock_get):
    mock_get.return_value = _mock_versions_payload()

    resolved = self.helper.resolve_version('libgit2-sys', '0.16.2')
    self.assertEqual('0.16.2+1.7.2', resolved)

  @mock.patch('osv.ecosystems.crates.RequestHelper.get')
  def test_resolve_version_no_change_when_unknown(self, mock_get):
    mock_get.return_value = _mock_versions_payload()

    resolved = self.helper.resolve_version('libgit2-sys', '1.0.0')
    self.assertEqual('1.0.0', resolved)


if __name__ == '__main__':  # pragma: no cover
  unittest.main()
