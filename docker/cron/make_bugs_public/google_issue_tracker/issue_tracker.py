# Copyright 2023 Google LLC
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

# pylint: disable=protected-access
"""Google issue tracker implementation."""

import enum

from google.auth import exceptions

from . import client

_NUM_RETRIES = 3


class IssueAccessLevel(str, enum.Enum):
  LIMIT_NONE = 'LIMIT_NONE'
  LIMIT_VIEW = 'LIMIT_VIEW'
  LIMIT_APPEND = 'LIMIT_APPEND'
  LIMIT_VIEW_TRUSTED = 'LIMIT_VIEW_TRUSTED'


class IssueTrackerError(Exception):
  """Base issue tracker error."""


class IssueTrackerNotFoundError(IssueTrackerError):
  """Not found error."""


class IssueTrackerPermissionError(IssueTrackerError):
  """Permission error."""


class IssueTracker:
  """Google issue tracker implementation."""

  def __init__(self, http_client):
    self._client = http_client

  @property
  def client(self):
    """HTTP Client."""
    if self._client is None:
      self._client = client.build()
    return self._client

  def _execute(self, request):
    """Executes a request."""
    http = None
    for _ in range(2):
      try:
        return request.execute(num_retries=_NUM_RETRIES, http=http)
      except exceptions.RefreshError:
        # Rebuild client and retry request.
        http = client.build_http()
        self._client = client.build('issuetracker', http=http)
        return request.execute(num_retries=_NUM_RETRIES, http=http)
      except client.HttpError as e:
        if e.resp.status == 404:
          raise IssueTrackerNotFoundError(str(e))
        if e.resp.status == 403:
          raise IssueTrackerPermissionError(str(e))
        raise IssueTrackerError(str(e))

  def get_issue(self, issue_id):
    """Gets the issue with the given ID."""
    return self._execute(self.client.issues().get(issueId=str(issue_id)))
