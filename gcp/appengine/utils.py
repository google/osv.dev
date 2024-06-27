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
from datetime import datetime
from dateutil.relativedelta import relativedelta
from dateutil import tz
from dateutil.parser import isoparse


def is_prod():
  # TODO(michaelkedar): Cloud Run/App Engine have different ways to check this
  # remove the App Engine header check when moving away from App Engine.
  # This function actually checks if it's running on gcp (on prod OR staging)
  # and it's only used for Redis cache (which has its own env vars) and logging.
  # Consider removing this altogether.
  return 'GAE_ENV' in os.environ or 'K_SERVICE' in os.environ


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
    value = isoparse(value)

  now = datetime.now(tz=tz.tzutc())
  diff = relativedelta(now, value)
  diff_seconds = (now - value).total_seconds()

  if diff_seconds < 60:
    return "just now"
  if diff_seconds < 3600:
    return f"{diff.minutes} minute{'s' if diff.minutes > 1 else ''} ago"
  if diff_seconds < 86400:
    return f"{diff.hours} hour{'s' if diff.hours > 1 else ''} ago"
  if diff_seconds < 172800:
    return "yesterday"
  if diff_seconds < 604800:
    return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
  if value.year == now.year:
    return value.strftime("%d %b")
  return value.strftime("%d %b %Y")
