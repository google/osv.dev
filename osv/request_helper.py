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
"""Request helpers"""

import requests
from requests.adapters import HTTPAdapter, Retry

from .cache import Cache

DEFAULT_BACKOFF_FACTOR = 5
DEFAULT_RETRY_TOTAL = 7
DEFAULT_REDIS_TTL_SECONDS = 6 * 60 * 60


class RequestError(Exception):
  """Exception raised by request helper when response is not 200"""
  response: requests.Response

  def __init__(self, response: requests.Response):
    self.response = response
    super().__init__(f'{response.status_code} Server Error: {response.reason} '
                     f'for url: {response.request.url}')


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
    """Getter method.

    Retrieves the text at the URL, using the cached result if available.

    Args:
      url: URL to retrieve

    Returns:
      the text at the URL.

    Raises:
      RequestError on a non-200 HTTP response.

    """
    if self.cache:
      cached_result = self.cache.get(url)
      if cached_result:
        return cached_result

    with requests.session() as session:
      retries = Retry(
          backoff_factor=self.backoff_factor,
          total=self.retry_total,
      )
      session.mount('https://', HTTPAdapter(max_retries=retries))
      session.headers.update({'User-Agent': 'osv.dev'})
      response = session.get(url)

      if response.status_code != 200:
        raise RequestError(response)

      text_response = response.text
      if self.cache:
        self.cache.set(url, text_response, self.cache_ttl)

      return text_response
