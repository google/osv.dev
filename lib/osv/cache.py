"""Caching interface and implementations"""

import redis


class Cache:
  """Cache Interface"""

  def get(self, key):
    raise NotImplementedError

  def set(self, key, value, expiry):
    raise NotImplementedError


class RedisCache(Cache):
  """Redis cache implementation."""

  redis_instance: redis.client.Redis

  def __init__(self, host, port):
    self.redis_instance = redis.Redis(host, port)

  def get(self, key):
    return self.redis_instance.get(key)

  def set(self, key, value, expiry):
    return self.redis_instance.set(key, value, ex=expiry)
