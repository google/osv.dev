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
"""Monorail client."""

import json

from google.oauth2 import service_account
from google.auth.transport import requests as google_requests
import requests

_API_BASE = 'https://api-dot-monorail-prod.appspot.com/prpc'
_TARGET_AUDIENCE = 'https://monorail-prod.appspot.com'
_XSSI_PREFIX = ')]}\'\n'
_TIMEOUT = 30  # HTTP(S) request timeout


class Client:
  """Monorail client."""

  def __init__(self, project, service_account_info):
    self.project = project
    self._service_account_info = service_account_info

  def get_issue(self, issue_id):
    """Get issue data."""
    credentials = service_account.IDTokenCredentials.from_service_account_info(
        self._service_account_info, target_audience=_TARGET_AUDIENCE)
    credentials.refresh(google_requests.Request())

    headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
    }
    credentials.apply(headers)

    url = f'{_API_BASE}/monorail.v3.Issues/GetIssue'
    body = {'name': f'projects/{self.project}/issues/{issue_id}'}

    resp = requests.post(url, json=body, headers=headers, timeout=_TIMEOUT)
    resp.raise_for_status()

    result = resp.text
    if result.startswith(_XSSI_PREFIX):
      result = result[len(_XSSI_PREFIX):]

    return json.loads(result)
