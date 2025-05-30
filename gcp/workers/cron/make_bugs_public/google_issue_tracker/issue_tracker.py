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

from __future__ import annotations

import enum
from typing import Any, Dict, Optional, Type # Added necessary types

from google.auth import exceptions as auth_exceptions # Alias for clarity
# Assuming googleapiclient.discovery.Resource is the type for the client object
from googleapiclient import discovery # For discovery.Resource

from . import client as http_client_builder # Alias to avoid confusion with self.client property

_NUM_RETRIES = 3


class IssueAccessLevel(str, enum.Enum): # This is fine, str mixin makes it behave like str
  LIMIT_NONE = 'LIMIT_NONE'
  LIMIT_VIEW = 'LIMIT_VIEW' # Publicly viewable by anyone.
  LIMIT_APPEND = 'LIMIT_APPEND' # Publicly viewable, specific groups can append.
  LIMIT_VIEW_TRUSTED = 'LIMIT_VIEW_TRUSTED' # Viewable by specific groups.
  # Other levels like LIMIT_EDIT, LIMIT_ADMIN, LIMIT_INTERNAL_VIEW exist.


class IssueTrackerError(Exception):
  """Base issue tracker error."""


class IssueTrackerNotFoundError(IssueTrackerError):
  """Not found error (HTTP 404)."""


class IssueTrackerPermissionError(IssueTrackerError):
  """Permission error (HTTP 403)."""


class IssueTracker:
  """Google issue tracker implementation."""

  # _client is a googleapiclient.discovery.Resource object, or None if not yet built.
  _client: Optional[discovery.Resource]

  # http_client_input can be an existing authorized HTTP client or None to build one.
  def __init__(self, http_client_input: Optional[Any] = None) -> None: # Renamed http_client
    # If http_client_input is provided, assume it's a discovery.Resource or compatible.
    # For simplicity, if it's not None, we assume it's the already built API client resource.
    # If client.py's build() returns Resource, then this is fine.
    # The property `client` will handle building if `_client` is None.
    if http_client_input is not None and isinstance(http_client_input, discovery.Resource):
        self._client = http_client_input
    elif http_client_input is not None: # If it's an HTTP lib object, build the service
        self._client = http_client_builder.build(http=http_client_input)
    else: # No client provided, will be built on first access
        self._client = None


  @property
  def client(self) -> discovery.Resource: # Returns a Resource object
    """HTTP Client. Builds on first access if not already built."""
    if self._client is None:
      # Uses the client module from this package to build a new HTTP client
      # and then the IssueTracker service resource.
      self._client = http_client_builder.build() # Default API is 'issuetracker'
    return self._client

  # The `request` parameter is an API request object, e.g., from self.client.issues().get().
  # These objects are specific to the google-api-python-client library.
  # Type `Any` is practical here. Return type is also `Any` (typically a Dict for JSON APIs).
  def _execute(self, request: Any) -> Any:
    """Executes a request with retries and error handling."""
    # Attempt to execute the request.
    # If credentials expire (RefreshError), rebuild the HTTP client and retry.
    # Handles common HTTP errors by raising specific IssueTracker exceptions.

    # The `http` parameter for `request.execute()` allows overriding the client's default http object.
    # This is used here to pass a newly built http object after a RefreshError.
    current_http_for_request: Optional[Any] = None # Start with default (None means use client's http)

    for attempt in range(2): # Try up to two times (initial + 1 retry on RefreshError)
      try:
        # http=None uses the client's default http object.
        # If current_http_for_request is set (after a RefreshError), it uses that.
        return request.execute(num_retries=_NUM_RETRIES, http=current_http_for_request)
      except auth_exceptions.RefreshError:
        # Credentials might have expired; try to refresh/rebuild the client.
        if attempt == 0: # Only retry once on RefreshError
          logging.info("Credentials refresh error, attempting to rebuild HTTP client and retry.")
          # Rebuild the underlying authorized HTTP object
          new_authorized_http = http_client_builder.build_http()
          # Rebuild the API service client resource with the new HTTP object
          # This updates self._client for subsequent calls too if needed by other methods.
          self._client = http_client_builder.build(http=new_authorized_http)
          # The request object itself was built with the old client.
          # To use the new _client's http, we need to pass it to execute().
          # If the request object is tied to the old client instance in a way that
          # simply passing a new http object to .execute() is not enough,
          # this might require rebuilding the `request` object itself using the new `self._client`.
          # For now, assume passing new http to .execute() is sufficient.
          # Or, more simply, just update self.client and retry the execute with its implicit http.
          # Let's try updating self.client's http object.
          # The `request` object was created from `self.client.issues().get()`.
          # If `self.client` (the service Resource) is rebuilt, the `request` object
          # should ideally be rebuilt too.
          # For simplicity here, we pass the `new_authorized_http` to the *next* execute call.
          # This implies the `request` object can accept a new `http` for its execution.
          current_http_for_request = new_authorized_http
          # Next iteration will use this new http object.
        else: # Failed even after retry
          logging.error("Credentials refresh error persisted after retry.")
          raise IssueTrackerError("Failed to refresh credentials after multiple attempts.") from None
      except http_client_builder.HttpError as e: # Catching HttpError aliased from client module
        if e.resp.status == 404:
          raise IssueTrackerNotFoundError(f"Issue not found: {e}") from e
        if e.resp.status == 403:
          raise IssueTrackerPermissionError(f"Permission denied for issue: {e}") from e
        # For other HTTP errors, raise a generic IssueTrackerError
        raise IssueTrackerError(f"HTTP error during issue tracker request: {e}") from e
      # Catch other googleapiclient errors if necessary, e.g., UnknownApiNameOrVersion
      except http_client_builder.UnknownApiNameOrVersion as e:
        raise IssueTrackerError(f"Issue tracker API discovery error: {e}") from e

    # Should not be reached if loop handles return or raise. Added for completeness.
    raise IssueTrackerError("Failed to execute request after all attempts.")


  def get_issue(self, issue_id: Union[str, int]) -> Dict[str, Any]:
    """Gets the issue with the given ID. Returns a dict representing the issue."""
    # The .issues().get() returns a request object. _execute runs it.
    # The result of execute() for a get request is typically a dict (parsed JSON).
    request_obj = self.client.issues().get(issueId=str(issue_id)) # issueId must be string
    return self._execute(request_obj)
