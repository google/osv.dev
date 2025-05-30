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

from __future__ import annotations

from typing import Any, Optional, Tuple # Added Optional, Tuple, Any

import google.auth
from google.auth import credentials as auth_credentials # For specific credential types
from google.auth import impersonated_credentials
import google_auth_httplib2 # For google_auth_httplib2.AuthorizedHttp
from googleapiclient import discovery # For discovery.Resource (service object)
from googleapiclient import errors
import httplib2 # For httplib2.Http

_DISCOVERY_URL = ('https://issuetracker.googleapis.com/$discovery/rest?'
                  'version=v1&labels=GOOGLE_PUBLIC')
_SCOPE = 'https://www.googleapis.com/auth/buganizer'
# OSS-Fuzz service account.
_IMPERSONATED_SERVICE_ACCOUNT = (
    '877343783628-compute@developer.gserviceaccount.com')
_REQUEST_TIMEOUT = 60 # In seconds

# Expose specific errors for convenience
HttpError = errors.HttpError
UnknownApiNameOrVersion = errors.UnknownApiNameOrVersion


def build_http() -> google_auth_httplib2.AuthorizedHttp:
  """Builds an authorized httplib2.Http object for service account impersonation."""
  # google.auth.default() returns (credentials, project_id)
  # Type for source_credentials can be more specific if known, e.g. google.auth.compute_engine.credentials.Credentials
  source_credentials: Optional[auth_credentials.Credentials]
  # project_id is Optional[str], ignored here with _
  source_credentials, _ = google.auth.default(scopes=[_SCOPE]) # Add scopes if default() needs it for source

  if not source_credentials:
      raise EnvironmentError("Could not get default Google credentials. "
                             "Ensure the environment is configured correctly for authentication.")

  # Create impersonated credentials
  impersonated_creds: impersonated_credentials.Credentials = impersonated_credentials.Credentials(
      source_credentials=source_credentials,
      target_principal=_IMPERSONATED_SERVICE_ACCOUNT,
      target_scopes=[_SCOPE],
      # lifetime can be specified if needed, defaults to 1 hour
  )

  # Create an httplib2.Http object with a timeout
  http_client: httplib2.Http = httplib2.Http(timeout=_REQUEST_TIMEOUT)

  # Return an AuthorizedHttp object using the impersonated credentials
  return google_auth_httplib2.AuthorizedHttp(credentials=impersonated_creds, http=http_client)


def _call_discovery(api_name: str, # Renamed api to api_name
                    http_client: google_auth_httplib2.AuthorizedHttp # Renamed http to http_client
                   ) -> discovery.Resource: # discovery.build returns a Resource object
  """Calls the discovery service to build a service object.

  Retries up to twice if there are any UnknownApiNameOrVersion errors (though this retry logic is not in the snippet).
  The snippet shows a direct call.
  """
  # discovery.build can raise errors.HttpError or errors.UnknownApiNameOrVersion
  service: discovery.Resource = discovery.build(
      serviceName=api_name, # Corrected parameter name from 'api' to 'serviceName'
      version='v1',
      discoveryServiceUrl=_DISCOVERY_URL,
      http=http_client,
      static_discovery=False # Use dynamic discovery
  )
  return service


def build(api_name: str = 'issuetracker', # Renamed api to api_name
          http_client: Optional[google_auth_httplib2.AuthorizedHttp] = None # Renamed http
         ) -> discovery.Resource: # Returns a service object (Resource)
  """Builds a Google API client for the specified API (e.g., issuetracker)."""
  # If an http client is not provided, build one with impersonation.
  current_http_client: google_auth_httplib2.AuthorizedHttp = http_client or build_http() # Renamed

  return _call_discovery(api_name, current_http_client)
