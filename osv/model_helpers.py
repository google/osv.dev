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
"""Datastore types."""

import datetime

from typing import List, Self

from google.cloud import ndb

# pylint: disable=relative-beyond-top-level
from .models import AliasGroup, AffectedEvent, SourceRepository, Bug
from . import ecosystems


def utcnow():
  """For mocking."""
  return datetime.datetime.utcnow()


def get_source_repository(source_name: str) -> SourceRepository:
  """Get source repository."""
  return SourceRepository.get_by_id(source_name)  # type: ignore


def sorted_events(ecosystem, range_type, events) -> list[AffectedEvent]:
  """Sort events."""
  if range_type == 'GIT':
    # No need to sort.
    return events

  if range_type == 'SEMVER':
    ecosystem_helper = ecosystems.SemverEcosystem()
  else:
    ecosystem_helper = ecosystems.get(ecosystem)

  if ecosystem_helper is None or not ecosystem_helper.supports_ordering:
    raise ValueError('Unsupported ecosystem ' + ecosystem)

  # Remove any magic '0' values.
  sorted_copy = []
  zero_event = None
  for event in events:
    if event.value == '0':
      zero_event = event
      continue

    sorted_copy.append(event)

  sorted_copy.sort(key=lambda e: ecosystem_helper.sort_key(e.value))
  if zero_event:
    sorted_copy.insert(0, zero_event)

  return sorted_copy


@ndb.tasklet
def get_aliases_async(bug_id: str) -> ndb.Future:
  """Gets aliases asynchronously."""
  alias_group = yield AliasGroup.query(AliasGroup.bug_ids == bug_id).get_async()
  return alias_group


@ndb.tasklet
def get_related_async(bug_id: str) -> ndb.Future:
  """Gets related bugs asynchronously."""
  related_bugs = yield Bug.query(Bug.related == bug_id).fetch_async()
  related_bug_ids = [bug.db_id for bug in related_bugs]
  return related_bug_ids
