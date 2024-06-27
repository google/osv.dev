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
"""Utils tests."""
import utils
import unittest
from datetime import datetime, timedelta
from dateutil.tz import tzutc
from unittest import mock


class TestRelativeTime(unittest.TestCase):
  """Check utils.relative_time() functionality"""

  def setUp(self):
    self.now = datetime.now(tz=tzutc())

  def test_just_now(self):
    """Check when the value is less than 1 min"""
    self.assertEqual(utils.relative_time(self.now), "just now")

  def test_minutes_ago(self):
    """Check when the value is less than one hour"""
    self.assertEqual(
        utils.relative_time(self.now - timedelta(minutes=5)), "5 minutes ago")

  def test_hours_ago(self):
    """Check when the value is less than 24 hours"""
    self.assertEqual(
        utils.relative_time(self.now - timedelta(hours=2)), "2 hours ago")

  def test_yesterday(self):
    """Check when the value is less than 48 hours"""
    self.assertEqual(
        utils.relative_time(self.now - timedelta(days=1)), "yesterday")

  def test_days_ago(self):
    """Check when the value is less than 7 days"""
    self.assertEqual(
        utils.relative_time(self.now - timedelta(days=3)), "3 days ago")

  def test_last_week(self):
    """Check when the value is 7 days"""
    last_week = self.now - timedelta(days=7)
    self.assertEqual(
        utils.relative_time(last_week), last_week.strftime("%d %b"))

  @mock.patch("utils.datetime")
  def test_date_without_year(self, mock_datetime):
    """Check when the value is longer than 7 days but in the same year"""
    now = datetime(2024, 6, 27, tzinfo=tzutc())
    mock_datetime.now.return_value = now
    date_within_year = now - timedelta(days=10)
    self.assertEqual(
        utils.relative_time(date_within_year),
        date_within_year.strftime("%d %b"))

  def test_date_with_year(self):
    date_outside_year = self.now - timedelta(days=400)
    self.assertEqual(
        utils.relative_time(date_outside_year),
        date_outside_year.strftime("%d %b %Y"))

  def test_iso_string(self):
    iso_string = (self.now - timedelta(days=3)).isoformat()
    self.assertEqual(utils.relative_time(iso_string), "3 days ago")


if __name__ == '__main__':
  unittest.main()
