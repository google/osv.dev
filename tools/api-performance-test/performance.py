#!/usr/bin/env python3
"""Mock API queries and send them to the test API endpoint for
performance testing. It is recommended to use two terminals to
run this script concurrently to generate sufficient traffic."""

import aiohttp
import asyncio
import os
import random
import sys
import time
import json

import osv

from google.cloud import ndb
from collections import Counter, defaultdict
from typing import Callable

BASE_URL = 'https://api.test.osv.dev/v1'
GCP_PROJECT = 'oss-vdb-test'
BUG_DIR = './all_bugs'

# Total run time in seconds
TOTAL_RUNTIME = 3600
# Execute all pending batch size requests within the specified time interval.
FREQUENCY_IN_SECONDS = 1

# Number of `vulnerability get` requests to send per second
VULN_QUERY_BATCH_SIZE = 50
# Number of `version query` requests to send per second
VERSION_QUERY_BATCH_SIZE = 100
# Number of `package query` requests to send per second
PACKAGE_QUERY_BATCH_SIZE = 30
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
    if not bug_dict['project']:
      self.packages = 'foo'
    else:
      self.packages = list(bug_dict['project'])
    self.purl = bug_dict['purl']
    if not bug_dict['ecosystem']:
      self.ecosystems = 'foo'
    else:
      self.ecosystems = list(bug_dict['ecosystem'])

    # Use the `affected fuzzy` value as the query version.
    # If no 'affected fuzzy' is present, assign a default value.
    self.affected_fuzzy = bug_dict['affected_fuzzy']
    if not self.affected_fuzzy:
      self.affected_fuzzy = '1.0.0'


def format_bug_for_output(bug: osv.Bug) -> dict[str, any]:
  """Outputs ndb bug query results to JSON file

  Args:
    bug: an `osv.Bug` queried from ndb.

  Returns:
    A dict storing all the important `Bug` fields that we want to use later
  """

  affected_fuzzy = None
  # Store one version for use as the query version later.
  if len(bug.affected_fuzzy) > 0:
    version_index = random.randrange(len(bug.affected_fuzzy))
    affected_fuzzy = bug.affected_fuzzy[version_index]

  return {
      'db_id': bug.db_id,
      'purl': bug.purl,
      'project': bug.project,
      'ecosystem': bug.ecosystem,
      'affected_fuzzy': affected_fuzzy
  }


def get_bugs_from_datastore() -> None:
  """Gets all bugs from the datastore and writes to `BUG_DIR`."""

  entries_per_file = 10000  # amount of bugs per file
  batch_size = 1000
  file_counter = 0
  os.makedirs(BUG_DIR, exist_ok=True)

  def write_to_json():
    """Writes to a new JSON file."""
    file_name = f'{BUG_DIR}/all_bugs_{file_counter}.json'
    with open(file_name, 'w+') as f:
      json.dump(results, f, indent=2)
    print(f'Saved {total_entries} entries to {file_name}')

  with ndb.Client(project=GCP_PROJECT).context():
    query = osv.Bug.query()
    query = query.filter(osv.Bug.status == osv.BugStatus.PROCESSED,
                         osv.Bug.public == True)  # pylint: disable=singleton-comparison
    print(f'Querying {query}')

    results = []
    total_entries = 0
    next_cursor = None

    while True:
      bugs, next_cursor, has_more = query.fetch_page(
          page_size=batch_size, start_cursor=next_cursor)
      if not has_more:
        break

      print(f'fetching {batch_size} entries.')
      results.extend([format_bug_for_output(bug) for bug in bugs])
      total_entries += len(bugs)

      # Write bugs to separate files in case the query fails or times out.
      if total_entries >= entries_per_file:
        write_to_json()

        # Reset for the next file
        results = []
        total_entries = 0
        file_counter += 1

    # Write any remaining entries to the last file
    if results:
      write_to_json()

  print(f'All results saved to {BUG_DIR}.')


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
      for ecosystem in bug.ecosystems:
        ecosystem_map[ecosystem].add(bug.db_id)
      for package in bug.packages:
        package_map[package].add(bug.db_id)
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
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=80, sock_read=80)
    if request_type == 'GET':
      async with session.get(request_url):
        pass  # We're not awaiting the response, just sending the request
    elif request_type == 'POST':
      async with session.post(request_url, json=request_body, timeout=timeout):
        # print(f'request: {request_body}, response: {response.status}')
        pass  # We're not awaiting the response, just sending the request
  except Exception as e:
    print(f'Error sending request {request_url} with body'
          f'{request_body}: {type(e)}')


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
  print(f'[{begin_time}] Running make request {payload_func.__name__} '
        f'for {TOTAL_RUNTIME} seconds')

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

  package = random.choice(bug_map[request_id].packages)
  ecosystem = random.choice(bug_map[request_id].ecosystems)
  return {"package": {"name": package, "ecosystem": ecosystem}}


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
  package = random.choice(bug_map[request_id].packages)
  ecosystem = random.choice(bug_map[request_id].ecosystems)
  return {
      "version": bug_map[request_id].affected_fuzzy,
      "package": {
          "name": package,
          "ecosystem": ecosystem
      }
  }


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
    query_type = random.choice(['version', 'package'])
    if query_type == 'version':
      query = build_version_payload(bug_id, bug_map)
    elif query_type == 'package':
      query = build_package_payload(bug_id, bug_map)
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
  if not os.path.exists(BUG_DIR):
    # This will take around 10 mins
    get_bugs_from_datastore()

  seed = random.randrange(sys.maxsize)
  # The seed value can be replaced for debugging
  random.seed(seed)
  print(f'Random seed {seed}')
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
  print(f'It will send vulnerability get requests for {len(vuln_query_ids)} '
        'vulnerabilities.')
  print('It will send package/version/batch query requests for '
        f'{len(package_query_ids)} packages within '
        f'{len(ecosystem_map)} ecosystems.')

  # Get all packages with the most frequently occurring number
  # of vulnerabilities.
  large_batch_query_ids = get_large_batch_query(package_map)

  await asyncio.gather(
      send_vuln_requests(vuln_query_ids, bug_map),
      send_package_requests(package_query_ids, bug_map),
      send_version_requests(package_query_ids, bug_map),
      send_batch_requests(package_query_ids, bug_map, BATCH_QUERY_BATCH_SIZE),
      send_batch_requests(large_batch_query_ids, bug_map,
                          LARGE_BATCH_QUERY_BATCH_SIZE))


if __name__ == "__main__":
  asyncio.run(main())
