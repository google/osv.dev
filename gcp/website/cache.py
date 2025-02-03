# Copyright 2022 Google LLC
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
"""Caching."""

import functools
import os
from typing import Callable
from concurrent.futures import ThreadPoolExecutor, Future

import flask_caching

import utils

if utils.is_cloud_run():
  instance = flask_caching.Cache(
      config={
          'CACHE_TYPE': 'RedisCache',
          'CACHE_REDIS_HOST': os.environ.get('REDISHOST', '127.0.0.1'),
          'CACHE_REDIS_PORT': int(os.environ.get('REDISPORT', 6379)),
      })
else:
  instance = flask_caching.Cache(config={
      'CACHE_TYPE': 'SimpleCache',
  })

_should_refresh_suffix = '__refresh_marker'
_executor_map: dict[str, ThreadPoolExecutor] = {}
_future_map: dict[str, Future] = {}


def smart_cache(
    key: str,
    hard_timeout: int,
    soft_timeout: int,
) -> Callable:
  """
  The decorated function will be cached with the given key. 

  If the decorated function is called any time after the `soft_timeout` 
  of the cache, the cached value will still be returned, but the cache 
  will be refreshed in an asynchronous background thread.

  Currently this decorator does not support differing arguments.
  """
  if key in _executor_map:
    raise ValueError('key already exists')

  # Only require one background thread to run per cache key
  # since we check whether an existing update task is already running
  # before queuing another update.
  _executor_map[key] = ThreadPoolExecutor(1)

  def decorator(f):

    @functools.wraps(f)
    def decorated_function(*args, **kwargs):

      def update_func():
        result = f(*args, **kwargs)
        instance.set(key, result, timeout=hard_timeout)
        instance.set(key + _should_refresh_suffix, True, timeout=soft_timeout)
        return result

      result = instance.get(key)
      if result is None:  # If the main cached value expires, refresh normally
        return update_func()

      # Only refresh the cached value once instance times out
      should_refresh_cached_value = not instance.has(key +
                                                     _should_refresh_suffix)
      future = _future_map.get(key)
      if should_refresh_cached_value and (future is None or future.done()):
        # Store the future to make sure it executes.
        # (Dropped futures are not executed)
        # Also for reference to prevent queueing up multiple updates
        _future_map[key] = _executor_map[key].submit(update_func)

      return result

    return decorated_function

  return decorator
