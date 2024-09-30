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
"""Gets a Google Issue Tracker HTTP client."""

import google.auth
from google.auth import impersonated_credentials
import google_auth_httplib2
from googleapiclient import discovery
from googleapiclient import errors
import httplib2

_DISCOVERY_URL = ('https://issuetracker.googleapis.com/$discovery/rest?'
                  'version=v1&labels=GOOGLE_PUBLIC')
_SCOPE = 'https://www.googleapis.com/auth/buganizer'
# OSS-Fuzz service account.
_IMPERSONATED_SERVICE_ACCOUNT = '877343783628-compute@developer.gserviceaccount.com'
_REQUEST_TIMEOUT = 60

HttpError = errors.HttpError
UnknownApiNameOrVersion = errors.UnknownApiNameOrVersion


def build_http():
  """Builds a httplib2.Http."""
  source_credentials, _ = google.auth.default()
  credentials = impersonated_credentials.Credentials(
      source_credentials=source_credentials,
      target_principal=_IMPERSONATED_SERVICE_ACCOUNT,
      target_scopes=[_SCOPE])

  return google_auth_httplib2.AuthorizedHttp(
      credentials, http=httplib2.Http(timeout=_REQUEST_TIMEOUT))


def _call_discovery(api, http):
  """Calls the discovery service.

  Retries upto twice if there are any UnknownApiNameOrVersion errors.
  """
  return discovery.build(
      api,
      'v1',
      discoveryServiceUrl=_DISCOVERY_URL,
      http=http,
      static_discovery=False)


def build(api='issuetracker', http=None):
  """Builds a google api client for buganizer."""
  if not http:
    http = build_http()
  return _call_discovery(api, http)
