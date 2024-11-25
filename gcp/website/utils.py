# Copyright 2022 Google LLC
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
"""Utils."""

import os
from datetime import datetime, UTC


def is_prod():
  # TODO(michaelkedar):
  # This function actually checks if it's running on gcp (on prod OR staging)
  # and it's only used for Redis cache (which has its own env vars) and logging.
  # Consider removing this altogether.
  return 'K_SERVICE' in os.environ


def relative_time(value: datetime | str) -> str:
  """
    Convert a datetime or ISO 8601 string to a human-readable relative time.

    Args:
        value: The input datetime as an ISO 8601 string or a datetime object.

    Returns:
        str: A human-readable string representing the relative time as:
             - < 1 minute: Just now
             - < 1 hour: x minutes ago
             - < 1 day: x days ago
             - < 2 day: yesterday
             - < 7 days: x days ago
             - >= 7 days: DD MMM
             - Year is not current year: DD MMM YYYY
    """
  # Parse the ISO 8601 string to a datetime object
  if isinstance(value, str):
    value = datetime.fromisoformat(value)

  now = datetime.now(tz=UTC)
  diff = now - value
  diff_seconds = diff.total_seconds()
  diff_minutes = diff_seconds // 60
  diff_hours = diff_seconds // (60 * 60)
  diff_days = diff_seconds // ((60 * 60) * 24)
  diff_weeks = diff_seconds // (((60 * 60) * 24) * 7)

  if diff_minutes == 0:
    return "just now"
  if diff_hours == 0:
    return f"{int(diff_minutes)} minute{'s' if diff_minutes > 1 else ''} ago"
  if diff_days == 0:
    return f"{int(diff_hours)} hour{'s' if diff_hours > 1 else ''} ago"
  if diff_days == 1:
    return "yesterday"
  if diff_weeks == 0:
    return f"{int(diff_days)} day{'s' if diff_days > 1 else ''} ago"
  if value.year == now.year:
    return value.strftime("%d %b")
  return value.strftime("%d %b %Y")
