#!/usr/bin/env python3
# Copyright 2024 Google LLC
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
"""Mock API queries and send them to the test API endpoint for
performance testing. It is recommended to use two terminals to
run this script concurrently to generate sufficient traffic."""

import logging
import aiohttp
import asyncio
import os
import random
import time
import json

from collections import Counter, defaultdict
from typing import Callable

import osv
import osv.logs

BASE_URL = 'https://api.test.osv.dev/v1'
GCP_PROJECT = 'oss-vdb-test'
BUG_DIR = './all_bugs'

# Total run time in seconds
TOTAL_RUNTIME = 3600 * 5  # 5 hours
# Execute all pending batch size requests within the specified time interval.
FREQUENCY_IN_SECONDS = 1

# Number of `vulnerability get` requests to send per second
VULN_QUERY_BATCH_SIZE = 50
# Number of `version query` requests to send per second
VERSION_QUERY_BATCH_SIZE = 80
# Number of `package query` requests to send per second
PACKAGE_QUERY_BATCH_SIZE = 20
# Number of `purl query` requests to send per second
PURL_QUERY_BATCH_SIZE = 30
# Number of `batch query` requests to send per second
BATCH_QUERY_BATCH_SIZE = 3
# Number of large `batch query` requests to send per second
LARGE_BATCH_QUERY_BATCH_SIZE = 2


class SimpleBug:
  """A simplified bug only contains essential information
  for making HTTP requests."""

  def __init__(self, bug_dict: dict):
    self.db_id = bug_dict['db_id']
    # If the package/ecosystem/version value is None, then add a fake value in.
    self.package = bug_dict.get('project', 'foo')
    self.ecosystem = bug_dict.get('ecosystem', 'foo')
    self.purl = bug_dict.get('purl', 'pkg:foo/foo')

    # Use the `affected fuzzy` value as the query version.
    # If no 'affected fuzzy' is present, assign a default value.
    self.affected_fuzzy = bug_dict.get('affected_fuzzy', '1.0.0')


def read_from_json(filename: str, ecosystem_map: defaultdict, bug_map: dict,
                   package_map: defaultdict) -> None:
  """Loads bugs from one JSON file into bug dicts.

  Args:
    filename: the JSON filename.

    ecosystem_map:
      A defaultdict mapping ecosystem names to their bugs. For example:
      {'Maven': (CVE-XXXX-XXXX, CVE-XXXX-XXXX), 'PyPI': ()}

    bug_map:
      A dict mapping bug ID to its `SimpleBug` object. For example:
      {'CVE-XXXX-XXXX,': SimpleBug{}}

    package_map:
      A defaultdict mapping package names to their bugs. For example:
      {'tensorflow': (CVE-XXXX-XXXX, CVE-XXXX-XXXX), 'curl': ()}

  Returns:
    None
  """
  with open(filename, "r") as f:
    json_file = json.load(f)
    for bug_data in json_file:
      bug = SimpleBug(bug_data)
      ecosystem_map[bug.ecosystem].add(bug.db_id)
      package_map[bug.package].add(bug.db_id)
      bug_map[bug.db_id] = bug


def load_all_bugs() -> tuple[defaultdict, dict, defaultdict]:
  """Loads bugs from JSON directory

  Returns:
    A defaultdict mapping ecosystem names to their bugs. For example:
    {'Maven': (CVE-XXXX-XXXX, CVE-XXXX-XXXX), 'PyPI': ()}

    A dict mapping bug ID to its `SimpleBug` object. For example:
    {'CVE-XXXX-XXXX,': SimpleBug{}}

    A defaultdict mapping package names to their bugs. For example:
    {'tensorflow': (CVE-XXXX-XXXX, CVE-XXXX-XXXX), 'curl': ()}
  """

  ecosystem_map = defaultdict(set)
  bug_map = {}
  package_map = defaultdict(set)
  for filename in os.listdir(BUG_DIR):
    if filename.endswith('.json'):
      file_path = os.path.join(BUG_DIR, filename)
      read_from_json(file_path, ecosystem_map, bug_map, package_map)
  return ecosystem_map, bug_map, package_map


async def make_http_request(session: aiohttp.ClientSession, request_url: str,
                            request_type: str, request_body: dict) -> None:
  """Makes one HTTP request

  Args:
    session:
      The HTTP ClientSession
    request_url:
      The HTTP request URL
    request_type:
      The HTTP request type: `GET` or `POST`
    request_body:
      The HTTP request body in JSON format
  """
  try:
    timeout = aiohttp.ClientTimeout(sock_connect=300, sock_read=300)
    if request_type == 'GET':
      async with session.get(request_url) as response:
        # Await the response to ensure the server has finished
        # and the connection is properly handled.
        await response.read()
    elif request_type == 'POST':
      async with session.post(
          request_url, json=request_body, timeout=timeout) as response:
        # Await the response to ensure the server has finished
        # and the connection is properly handled.
        await response.read()
  except Exception as e:
    # When sending a large number of requests concurrently,
    # some may fail due to timeout issues.
    # These failures can be ignored as long as the server receives a
    # sufficient volume of successful requests.
    logging.warning('Error sending request %s with body %s: %s', request_url,
                    request_body, type(e))


async def make_http_requests_async(request_ids: list, bug_map: dict, url: str,
                                   batch_size: int,
                                   payload_func: Callable) -> None:
  """Makes the required number of HTTP requests per second async.

  Args:
    request_ids:
      A list of bug IDs
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects
    url:
      The request URL
    batch_size:
      The number of requests to make per second
    payload_func:
      The payload function, such as `build_batch_payload`
  """

  begin_time = time.monotonic()
  logging.info('[%s] Running make request %s for %d seconds', begin_time,
               payload_func.__name__, TOTAL_RUNTIME)

  total_run_time = time.monotonic() - begin_time
  index = 0
  length = len(request_ids)
  async with aiohttp.ClientSession() as session:
    while total_run_time < TOTAL_RUNTIME:
      start_time = time.monotonic()

      batch_request_ids = request_ids[index:batch_size + index]
      if payload_func.__name__ == build_vulnerability_payload.__name__:
        for request_id in batch_request_ids:
          # OSV getting vulnerability detail is a GET request
          asyncio.create_task(
              make_http_request(session, f'{url}/{request_id}', 'GET',
                                payload_func()))
      elif payload_func.__name__ == build_batch_payload.__name__:
        for _ in range(0, batch_size):
          asyncio.create_task(
              make_http_request(session, url, 'POST',
                                payload_func(request_ids, bug_map)))
      else:
        for request_id in batch_request_ids:
          asyncio.create_task(
              make_http_request(session, url, 'POST',
                                payload_func(request_id, bug_map)))
      index += batch_size
      if index >= length:
        index = 0

      end_time = time.monotonic()
      time_elapsed = end_time - start_time
      if time_elapsed < FREQUENCY_IN_SECONDS:
        await asyncio.sleep(FREQUENCY_IN_SECONDS - time_elapsed)
      total_run_time = time.monotonic() - begin_time


def build_vulnerability_payload() -> None:
  """The vulnerability query doesn't need a request body"""
  return None


def build_package_payload(request_id: str, bug_map: dict) -> dict[str, any]:
  """Builds a package query payload

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects

  Returns:
    A dict containing package query payload, example:
    '"package": {"name": "mruby","ecosystem": "OSS-Fuzz"}}'
  """

  return {
      "package": {
          "name": bug_map[request_id].package,
          "ecosystem": bug_map[request_id].ecosystem
      }
  }


def build_version_payload(request_id: str, bug_map: dict) -> dict:
  """Builds a version query payload

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects

  Returns:
    A dict containing package version query payload, example:
    '{"package": {
      "name": "mruby","ecosystem": "OSS-Fuzz"}, "version": "2.1.2rc"}'
  """

  return {
      "version": bug_map[request_id].affected_fuzzy,
      "package": {
          "name": bug_map[request_id].package,
          "ecosystem": bug_map[request_id].ecosystem
      }
  }


def build_purl_payload(request_id: str, bug_map: dict) -> dict:
  """Builds a purl query payload

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects

  Returns:
    A dict containing package version query payload, example:
    '{"package": {"purl": "pkg:golang/github.com/golang-jwt/jwt/v4@4.5.1"}}'
  """
  purl = bug_map[request_id].purl
  purl_with_version = f'{purl}@{bug_map[request_id].affected_fuzzy}'

  # Use random.choice to select between the two PURL options
  chosen_purl = random.choice([purl, purl_with_version])

  return {"package": {"purl": chosen_purl,}}


def build_batch_payload(request_ids: list,
                        bug_map: dict) -> dict[str, list[dict[str, any]]]:
  """Builds a batch query payload

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects

  Returns:
    A dict containing OSV batch query payload, example:
    '{
        "queries": [
          {
            "package": {
              ...
            },
            "version": ...
          },
          {
            "package": {
              ...
            },
            "version": ...
          },
        ]
      }'
  """
  size = random.randint(1, 100)
  batch_ids = random.sample(request_ids, min(size, len(request_ids)))
  queries = []
  for bug_id in batch_ids:
    query = {}
    query_type = random.choice(['version', 'package', 'purl'])
    if query_type == 'version':
      query = build_version_payload(bug_id, bug_map)
    elif query_type == 'package':
      query = build_package_payload(bug_id, bug_map)
    elif query_type == 'purl':
      query = build_purl_payload(bug_id, bug_map)
    queries.append(query)

  return {"queries": [queries]}


def get_large_batch_query(package_map: defaultdict) -> list[str]:
  """Gets a list of bug IDs for large batch queries. 
  This list contains bug IDs from the packages with the high
  number of vulnerabilities.

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects

  Returns:
    A dict containing OSV batch query payload, example:
    '{
        "queries": [
          {
            "package": {
              ...
            },
            "version": ...
          },
          {
            "package": {
              ...
            },
            "version": ...
          },
        ]
      }'
  """
  most_common = 5000
  package_counter = Counter()
  for package in package_map:
    # filter out invalid package name and Linux Kernel
    if package in ('foo', 'Kernel'):
      continue
    package_counter[package] = len(package_map[package])
  most_vulnerable_packages = package_counter.most_common(most_common)
  large_batch_query_ids = []
  for package, package_count in most_vulnerable_packages:
    if package_count == 0:
      break
    large_batch_query_ids.append(package_map[package].pop())

  random.shuffle(large_batch_query_ids)
  return large_batch_query_ids


async def send_version_requests(request_ids: list, bug_map: dict) -> None:
  """Sends version query requests

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects
  """

  url = f'{BASE_URL}/query'
  batch_size = VERSION_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 build_version_payload)


async def send_package_requests(request_ids: list, bug_map: dict) -> None:
  """Sends package query requests

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects
  """
  url = f'{BASE_URL}/query'
  batch_size = PACKAGE_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 build_package_payload)


async def send_purl_requests(request_ids: list, bug_map: dict) -> None:
  """Sends purl query requests

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects
  """
  url = f'{BASE_URL}/query'
  batch_size = PURL_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 build_purl_payload)


async def send_vuln_requests(request_ids: list, bug_map: dict) -> None:
  """Sends vulnerability get requests

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects
  """
  url = f'{BASE_URL}/vulns'
  batch_size = VULN_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 build_vulnerability_payload)


async def send_batch_requests(request_ids: list, bug_map: dict,
                              batch_size: int) -> None:
  """Sends batch query requests

  Args:
    request_id:
      The bug ID
    bug_map:
      A dict mapping bug IDs to the corresponding `SimpleBug` objects
    batch_size:
      The batch query size
  """
  url = f'{BASE_URL}/querybatch'
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 build_batch_payload)


async def main() -> None:
  osv.logs.setup_gcp_logging('staging-test')
  seed = random.randrange(1000)
  logging.info('Random seed %d', seed)
  # Log the seed value. This allows us to use the same seed later
  # and reproduce this random result for debugging purposes.
  random.seed(seed)

  # The `ecosystem_map` can be used to filter our queries for a
  # specific ecosystem.
  ecosystem_map, bug_map, package_map = load_all_bugs()
  vuln_query_ids = list(bug_map.keys())
  package_query_ids = []
  for package in package_map:
    # Tests each package once.
    package_query_ids.append(package_map[package].pop())
  random.shuffle(package_query_ids)
  random.shuffle(vuln_query_ids)
  logging.info(
      'It will send vulnerability get requests for %d vulnerabilities.',
      len(vuln_query_ids))
  logging.info(
      'It will send package/version/batch query requests for '
      '%d packages within %d ecosystems.', len(package_query_ids),
      len(ecosystem_map))

  # Get all packages with the most frequently occurring number
  # of vulnerabilities.
  large_batch_query_ids = get_large_batch_query(package_map)

  await asyncio.gather(
      send_vuln_requests(vuln_query_ids, bug_map),
      send_package_requests(package_query_ids, bug_map),
      send_version_requests(package_query_ids, bug_map),
      send_purl_requests(package_query_ids, bug_map),
      send_batch_requests(package_query_ids, bug_map, BATCH_QUERY_BATCH_SIZE),
      send_batch_requests(large_batch_query_ids, bug_map,
                          LARGE_BATCH_QUERY_BATCH_SIZE),
      return_exceptions=True)


if __name__ == "__main__":
  asyncio.run(main())
