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
        str: A human-readable string representing the relative time 
             (e.g., '2 days ago').
    """
  # Parse the ISO 8601 string to a datetime object
  if isinstance(value, str):
    value = isoparse(value)

  now = datetime.now(tz=tz.tzutc())
  diff = relativedelta(now, value)

  if diff.years > 0:
    return f"{diff.years} year{'s' if diff.years > 1 else ''} ago"
  if diff.months > 0:
    return f"{diff.months} month{'s' if diff.months > 1 else ''} ago"
  if diff.days > 0:
    return f"{diff.days} day{'s' if diff.days > 1 else ''} ago"
  if diff.hours > 0:
    return f"{diff.hours} hour{'s' if diff.hours > 1 else ''} ago"
  if diff.minutes > 0:
    return f"{diff.minutes} minute{'s' if diff.minutes > 1 else ''} ago"
  if diff.seconds > 0:
    return f"{diff.seconds} second{'s' if diff.seconds > 1 else ''} ago"
  return "just now"
