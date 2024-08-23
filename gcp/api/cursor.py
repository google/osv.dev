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

import base64
from enum import Enum
from typing import Self
import typing

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
  This cursor should be initialized every time a pageable 
  query.iter() is called.

  Allows us to represent the "starting" cursor.

  This type could have 3 states encoded in _QueryCursorState.
  If the current state is IN_PROGRESS, self.cursor will not be None.
  """

  cursor: ndb.Cursor | None = None
  cursor_state: _QueryCursorState = _QueryCursorState.ENDED
  query_number: int = 1

  def __init__(self, query_number: int) -> None:
    self.query_number = query_number
    pass

  @classmethod
  def from_page_token(cls, page_token: str | None) -> Self:
    """Generate a query cursor from a url safe page token."""
    qc = cls(0)

    if not page_token:
      qc.cursor_state = _QueryCursorState.STARTED
      qc.cursor = None
      return qc

    split_values = page_token.split(_METADATA_SEPARATOR, 1)
    if len(split_values) == 2:
      page_token = split_values[1]
      try:
        qc.query_number = int(split_values[0])
      except ValueError as e:
        raise ValueError('Invalid page token.') from e

    if not page_token or page_token == _FIRST_PAGE_TOKEN:
      qc.cursor_state = _QueryCursorState.STARTED
      qc.cursor = None
      return qc

    qc.cursor = ndb.Cursor(urlsafe=page_token)
    qc.cursor_state = _QueryCursorState.IN_PROGRESS
    return qc

  def update_from_iterator(self, it: ndb.QueryIterator) -> None:
    try:
      self.cursor = typing.cast(ndb.Cursor, it.cursor_after())
      self.cursor_state = _QueryCursorState.IN_PROGRESS
    except ndb_exceptions.BadArgumentError:
      self.cursor = None
      self.cursor_state = _QueryCursorState.STARTED

  def get_cursor(self) -> ndb.Cursor | None:
    if self.cursor_state == _QueryCursorState.IN_PROGRESS:
      return self.cursor

    return None

  def ended(self) -> bool:
    return self.cursor_state == _QueryCursorState.ENDED

  def url_safe_encode(self) -> str | None:
    """Create a url safe page token to pass back to the API caller"""
    cursor_part: str = ''
    match self.cursor_state:
      case _QueryCursorState.STARTED:
        cursor_part = _FIRST_PAGE_TOKEN
      case _QueryCursorState.IN_PROGRESS:
        # Assume that IN_PROGRESS means self.cursor is always set.
        # Loudly throw an exception if this is not the case
        cursor_part = self.cursor.urlsafe().decode()  # type: ignore
      case _QueryCursorState.ENDED:
        # If ENDED, we want to return None to not include
        # a token in the response
        return None

    if self.query_number == 0:
      return cursor_part

    return str(self.query_number) + _METADATA_SEPARATOR + cursor_part
