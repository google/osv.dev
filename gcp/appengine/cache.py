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

import os

import flask_caching

import utils

if utils.is_prod():
  instance = flask_caching.Cache(
      config={
          'CACHE_TYPE': 'RedisCache',
          'CACHE_REDIS_HOST': os.environ.get('REDISHOST', 'localhost'),
          'CACHE_REDIS_PORT': int(os.environ.get('REDISPORT', 6379)),
      })
else:
  instance = flask_caching.Cache(config={
      'CACHE_TYPE': 'SimpleCache',
  })
