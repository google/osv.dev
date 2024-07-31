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
import functools
import inspect
import json
import typing


class Cache:
  """Cache Interface"""

  def get(self, key):
    raise NotImplementedError

  def set(self, key, value, ttl):
    raise NotImplementedError


class _CacheEntry:
  data: typing.Any
  # TODO(rexpan):
  #  Add more complex expiry logic by checking Last-Modified headers
  expiry: float

  def __init__(self, data, ttl):
    self.data = data
    self.expiry = datetime.datetime.now().timestamp() + ttl


def _check_json_serializable(obj):
  """Raise exception if `obj` is not JSON serializable."""
  # Cache implementations require keys and values to be JSON serializable.
  json.dumps(obj)


class InMemoryCache(Cache):
  """In memory cache implementation."""

  key_val_map: typing.Dict[str, _CacheEntry]

  def __init__(self):
    self.key_val_map = {}

  def get(self, key):
    entry = self.key_val_map.get(key)
    if not entry:
      return None

    if entry.expiry >= datetime.datetime.now().timestamp():
      return entry.data

    self.key_val_map.pop(key)
    return None

  def set(self, key, value, ttl):
    self.key_val_map[key] = _CacheEntry(value, ttl)


def cached(cache: Cache, ttl: int = 60 * 60):
  """Function decorator to cache results.

  Args:
    cache: Cache object to store information, each function also has a unique
      key for values cached, therefore you can safely share the same cache
      object across different functions.
    ttl: Time to live in seconds (default 1 hour).
  """

  def decorator(func):
    # Get the name of the function decorated, this will be used as the key in
    # the cache.
    unique_f_key = ('FUNC_MODULE_NAME', inspect.getmodule(func).__name__,
                    func.__qualname__)

    @functools.wraps(func)
    def wrapper(*args, **kwargs):
      # TODO(ochang): Detect and handle `self` arguments.
      sig = inspect.signature(func)
      # Passing through the arguments made to the function
      bound_args = sig.bind(*args, **kwargs)
      # Apply the default since the cache could be external (Redis)
      # If default changes, we want a new key to be generated
      bound_args.apply_defaults()
      # Making it hashable and combining it with the function name
      cache_key = (*bound_args.arguments.items(), unique_f_key)
      _check_json_serializable(cache_key)
      cached_value = cache.get(cache_key)
      if cached_value:
        return cached_value

      # Cache miss, cache the return value from the decorated function
      value = func(*args, **kwargs)
      _check_json_serializable(value)
      cache.set(cache_key, value, ttl)

      return value

    return wrapper

  return decorator
