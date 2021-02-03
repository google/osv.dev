#!/usr/bin/env python3
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
"""OSV Importer."""

from google.cloud import ndb

# pylint: disable=relative-beyond-top-level
from . import types


def get_source_repository(source_name):
  """Get source repository."""
  return ndb.Key(types.SourceRepository, source_name).get()


def parse_source_id(source_id):
  """Get the source name and id from source_id."""
  return source_id.split(':', 1)
