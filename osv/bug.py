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
"""Bug helpers."""

from __future__ import annotations

import enum
import re
from typing import Any, Dict, List


class BugStatus(enum.IntFlag):
  """Bug status."""

  UNPROCESSED = 0
  PROCESSED = 1
  INVALID = 2


# Groups of numbers, or {RC,alpha,beta,preview}<optional number>. Include a
# negative lookbehind to avoid catching cases like "arc" which may be part of a
# project name.
VERSION_COMPONENT_REGEX = re.compile(
    r'(\d+|(?<![a-z])(?:rc|alpha|beta|preview)\d*)', re.IGNORECASE)


def normalize_tag(tag: str) -> str:
  """Normalize a single tag for fuzzy version searching."""
  components: List[str] = VERSION_COMPONENT_REGEX.findall(tag)
  return '-'.join(components)


def normalize_tags(tags: List[str]) -> List[str]:
  """Normalize tags for fuzzy version searching."""
  return [normalize_tag(tag) for tag in tags]


def populate_indices(bug: Dict[str, Any]) -> None:
  """Write search indices for the bug."""
  bug['has_affected'] = bool(bug.get('affected'))

  search_indices: List[str] = []
  project: str | None = bug.get('project')
  if project:
    search_indices.append(project)

  # Assuming bug.key.id_or_name is a string.
  # If bug is an NDB model, this might need a more specific type
  # but Dict[str, Any] for bug means we assume string keys for now.
  bug_id: str = bug.key.id_or_name
  search_indices.append(bug_id)
  search_indices.extend(bug_id.split('-'))
  bug['search_indices'] = search_indices
