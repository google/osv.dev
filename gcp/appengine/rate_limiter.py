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
"""Basic rate limiter."""

import datetime

import redis


class RateLimiter:
  """Rate limiter."""

  def __init__(self, redis_host, redis_port, requests_per_min):
    self._redis = redis.Redis(redis_host, redis_port)
    self._requests_per_min = requests_per_min

  def check_request(self, ip_addr):
    """Check a request. Returns whether or not the request should proceed."""
    minute = datetime.datetime.utcnow().minute
    key_name = f'{ip_addr}:{minute}'

    with self._redis.pipeline():
      counter = self._redis.incr(key_name)
      self._redis.expire(key_name, 59)

    return counter <= self._requests_per_min
