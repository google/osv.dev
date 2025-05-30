# Copyright 2024 Google LLC
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
"""OSV API server cursor implementation."""

from __future__ import annotations

import base64
from enum import Enum
from typing import Optional, Self, cast # Removed `import typing`, use `cast` from `typing`

from google.cloud import ndb
import google.cloud.ndb.exceptions as ndb_exceptions

_FIRST_PAGE_TOKEN = base64.urlsafe_b64encode(b'FIRST_PAGE_TOKEN').decode()
# Use ':' as the separator as it doesn't appear in urlsafe_b64encode
# (which is what is used for both _FIRST_PAGE_TOKEN, and ndb.Cursor.urlsafe())
_METADATA_SEPARATOR = ':'


class _QueryCursorState(Enum):
  """
  Stores the 3 states a query cursor can be in.
  """

  # The cursor has reached the end, no need to return to the user
  ENDED = 0
  # The cursor is at the very start of the query, no cursor needs to be
  # set when querying ndb
  STARTED = 1
  # ndb.Cursor is set and in progress
  IN_PROGRESS = 2


class QueryCursor:
  """
  Custom cursor class that wraps the ndb cursor.
  Allows us to represent the "starting" cursor.

  The default state is ENDED with no ndb.Cursor.

  This type could have 3 states encoded in _QueryCursorState.
  If the current state is IN_PROGRESS, self.cursor will not be None.

  Attributes:
    query_number: This cursor is specifically for the Nth ndb datastore
      query in the current query request. (Starts from 1)
    ndb_cursor: Get the internal ndb_cursor. This could be None.
    ended: Whether this cursor is for a query that has finished returning data.
  """

  _ndb_cursor: Optional[ndb.Cursor] = None # Changed to Optional[ndb.Cursor]
  _cursor_state: _QueryCursorState = _QueryCursorState.ENDED
  # The first query is numbered 1. This is because the query counter is
  # incremented **before** the query and the query number being used.
  query_number: int = 1

  @classmethod
  def from_page_token(cls, page_token: str | None) -> Self:
    """Generate a query cursor from a url safe page token."""
    qc = cls()

    if not page_token:
      qc._cursor_state = _QueryCursorState.STARTED
      qc._ndb_cursor = None
      return qc

    split_values = page_token.split(_METADATA_SEPARATOR, 1)
    if len(split_values) == 2:
      page_token = split_values[1]
      try:
        qc.query_number = int(split_values[0])
      except ValueError as e:
        raise ValueError('Invalid page token.') from e

    if not page_token or page_token == _FIRST_PAGE_TOKEN:
      qc._cursor_state = _QueryCursorState.STARTED
      qc._ndb_cursor = None
      return qc

    qc._ndb_cursor = ndb.Cursor(urlsafe=page_token)
    qc._cursor_state = _QueryCursorState.IN_PROGRESS
    return qc

  def update_from_iterator(self, it: ndb.QueryIterator) -> None:
    """
    Update the current cursor from the value of the ndb.iterator passed in.

    Args:
      it: the iterator to take the cursor position from.
    """
    try:
      # Use cast from typing directly
      self._ndb_cursor = cast(ndb.Cursor, it.cursor_after())
      self._cursor_state = _QueryCursorState.IN_PROGRESS
    except ndb_exceptions.BadArgumentError:
      # This exception can happen when iterator has not begun iterating
      # and it.next() is the very first element.
      #
      # In those cases, `cursor_after()`` would not be 'after' any element,
      # throwing this exception.

      # We represent this by setting the state to STARTED.
      self._ndb_cursor = None
      self._cursor_state = _QueryCursorState.STARTED

  @property
  def ndb_cursor(self) -> ndb.Cursor | None:
    """The inner ndb cursor, could be None"""
    if self._cursor_state == _QueryCursorState.IN_PROGRESS:
      return self._ndb_cursor

    return None

  @property
  def ended(self) -> bool:
    """
    Whether the cursor has finished or not.
    """
    return self._cursor_state == _QueryCursorState.ENDED

  def url_safe_encode(self) -> str | None:
    """
    Create a url safe page token to pass back to the API caller.
    """
    cursor_part: str = ''
    match self._cursor_state:
      case _QueryCursorState.STARTED:
        cursor_part = _FIRST_PAGE_TOKEN
      case _QueryCursorState.IN_PROGRESS:
        # Ensure _ndb_cursor is not None when in this state, as per class logic.
        if self._ndb_cursor is None:
          # This case should ideally not be reached if state is managed correctly.
          raise ValueError("_ndb_cursor cannot be None when state is IN_PROGRESS")
        cursor_part = self._ndb_cursor.urlsafe().decode()
      case _QueryCursorState.ENDED:
        # If ENDED, we want to return None to not include
        # a token in the response
        return None

    return str(self.query_number) + _METADATA_SEPARATOR + cursor_part
