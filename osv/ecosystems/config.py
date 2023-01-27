import typing

from ..cache import Cache

TIMEOUT = 30  # Timeout for HTTP(S) requests
use_deps_dev = False
deps_dev_api_key = ''
# Used for checking out git repositories
# Intended to be set in worker.py
work_dir: typing.Optional[str] = None

shared_cache: typing.Optional[Cache] = None


def set_cache(cache: typing.Optional[Cache]):
  """Configures and enables the redis caching layer"""
  global shared_cache
  shared_cache = cache