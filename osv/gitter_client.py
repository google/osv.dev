# Copyright 2026 Google LLC
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
"""Functions for interacting with Gitter."""

import requests

from . import repository_pb2
from .vulnerability_pb2 import Range
from .repos import gitter_host, RepoInaccessibleError, _git_mirror

# To regenerate the gitter repository python bindings:
# pylint: disable=line-too-long
# poetry run python3 -m grpc_tools.protoc --proto_path=../go/cmd/gitter/pb/repository/ --python_out=. --mypy_out=. ../go/cmd/gitter/pb/repository/repository.proto


def get_affected_commits(
    affected_range: Range,
    detect_cherrypicks=True
) -> tuple[list[str], list[bytes], list[repository_pb2.Event]]:
  """
    Get affected commits and tags from Gitter.
    
    Args:
        affected_range: The range to get affected commits for.
        detect_cherrypicks: Whether to detect cherrypicks.
    
    Returns:
        A tuple of (versions, cherry_picked_events).
    Raises:
        RuntimeError: If GITTER_HOST is not set.
        ValueError: If affected_range.type is not GIT or repo is not set.
        RepoInaccessibleError: If Gitter reports that the repo is inaccessible.
    """
  if not gitter_host():
    raise RuntimeError('GITTER_HOST not set')
  if affected_range.type != Range.GIT:
    raise ValueError('Range type must be GIT')
  if not affected_range.repo:
    raise ValueError('No repo in range')

  gitter_request = repository_pb2.AffectedCommitsRequest(
      url=_git_mirror(affected_range.repo),
      detect_cherrypicks_fixed=detect_cherrypicks,
      detect_cherrypicks_introduced=detect_cherrypicks,
      detect_cherrypicks_limit=detect_cherrypicks,
  )
  for event in affected_range.events:
    if event.introduced:
      gitter_request.events.append(
          repository_pb2.Event(
              event_type=repository_pb2.EventType.INTRODUCED,
              hash=event.introduced,
          ))
    if event.fixed:
      gitter_request.events.append(
          repository_pb2.Event(
              event_type=repository_pb2.EventType.FIXED,
              hash=event.fixed,
          ))
    if event.limit:
      gitter_request.events.append(
          repository_pb2.Event(
              event_type=repository_pb2.EventType.LIMIT,
              hash=event.limit,
          ))
    if event.last_affected:
      gitter_request.events.append(
          repository_pb2.Event(
              event_type=repository_pb2.EventType.LAST_AFFECTED,
              hash=event.last_affected,
          ))

  response = requests.post(
      f'{gitter_host()}/affected-commits',
      data=gitter_request.SerializeToString(),
      headers={'Content-Type': 'application/x-protobuf'},
      timeout=3600,
  )
  if response.status_code == 403:
    raise RepoInaccessibleError(f'Gitter returned error: {response.text}')
  if response.status_code != 200:
    raise RuntimeError(f'Gitter returned error: {response.text}')

  gitter_response = repository_pb2.AffectedCommitsResponse()
  gitter_response.ParseFromString(response.content)
  versions: list[str] = []
  for tag in gitter_response.tags:
    versions.append(tag.label)
  commits: list[bytes] = []
  for commit in gitter_response.commits:
    commits.append(commit.hash)

  return versions, commits, gitter_response.cherry_picked_events
