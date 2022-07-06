"""Request helpers"""

import requests
from requests.adapters import HTTPAdapter, Retry

from .cache import Cache

DEFAULT_BACKOFF_FACTOR = 5
DEFAULT_RETRY_TOTAL = 7
DEFAULT_REDIS_TTL_SECONDS = 6 * 60 * 60


class RequestException(Exception):
  response: requests.Response

  def __init__(self, response: requests.Response):
    self.response = response
    super().__init__()


class RequestHelper:
  """Request helper that manages caching and automatic retries"""
  retry_total: int
  backoff_factor: int
  cache: Cache = None
  cache_ttl: int

  def __init__(self,
               cache=None,
               backoff_factor=DEFAULT_BACKOFF_FACTOR,
               retry_total=DEFAULT_RETRY_TOTAL,
               cache_ttl=DEFAULT_REDIS_TTL_SECONDS):
    self.backoff_factor = backoff_factor
    self.retry_total = retry_total
    self.cache_ttl = cache_ttl
    self.cache = cache

  def get(self, url):
    if self.cache is not None:
      cached_result = self.cache.get(url)
      if cached_result is not None:
        return cached_result

    session = requests.session()
    retries = Retry(
        backoff_factor=self.backoff_factor,
        total=self.retry_total,
    )
    session.mount('https://', HTTPAdapter(max_retries=retries))
    response = session.get(url)

    if response.status_code != 200:
      raise RequestException(response)

    text_response = response.text
    if self.cache is not None:
      self.cache.set(url, text_response, self.cache_ttl)

    return text_response
