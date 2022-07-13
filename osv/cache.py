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
"""Caching interface and implementations"""
import datetime
import typing


class Cache:
  """Cache Interface"""

  def get(self, key):
    raise NotImplementedError

  def set(self, key, value, ttl):
    raise NotImplementedError


class _CacheEntry:
  data: typing.Any
  expiry: float

  def __init__(self, data, ttl):
    self.data = data
    self.expiry = datetime.datetime.now().timestamp() + ttl


class InMemoryCache(Cache):
  """In memory cache implementation."""

  key_val_map: typing.Dict[str, _CacheEntry]

  def __init__(self):
    self.key_val_map = dict()

  def get(self, key):
    entry = self.key_val_map.get(key)
    if not entry:
      return None

    if entry.expiry >= datetime.datetime.now().timestamp():
      return entry.data
    else:
      self.key_val_map.pop(key)
      return None

  def set(self, key, value, ttl):
    self.key_val_map[key] = _CacheEntry(value, ttl)
