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

from __future__ import annotations

import logging
import aiohttp # For aiohttp.ClientSession, aiohttp.ClientTimeout
import asyncio
import os
import random
import time
import json
from collections import Counter, defaultdict # Counter needs import
from typing import Any, Callable, Coroutine, DefaultDict, Dict, List, Optional, Set, Tuple # Added necessary types

# osv module here likely refers to the main osv package, not specific models directly
# For specific model types, direct import or more qualified name might be needed if used.
# However, this script defines its own SimpleBug.
# import osv
import osv.logs # For osv.logs.setup_gcp_logging

BASE_URL: str = 'https://api.test.osv.dev/v1'
GCP_PROJECT: str = 'oss-vdb-test' # Should this be configurable or env var?
BUG_DIR: str = './all_bugs' # Path to directory containing bug JSON files

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
  """A simplified bug representation containing only essential information
  for making HTTP requests during performance testing."""

  db_id: str
  package: str
  ecosystem: str
  purl: str
  affected_fuzzy: str # Typically a version string

  def __init__(self, bug_dict: Dict[str, Any]) -> None:
    self.db_id = str(bug_dict['db_id']) # Ensure db_id is string
    # Provide defaults if original data might be missing these fields
    self.package = str(bug_dict.get('project', 'foo')) # 'project' in JSON maps to package name
    self.ecosystem = str(bug_dict.get('ecosystem', 'foo'))
    self.purl = str(bug_dict.get('purl', 'pkg:foo/foo'))

    # Use the `affected_fuzzy` list's first element if available, else default.
    # Assuming affected_fuzzy is a list of strings.
    affected_fuzzy_list = bug_dict.get('affected_fuzzy', [])
    if isinstance(affected_fuzzy_list, list) and affected_fuzzy_list:
        self.affected_fuzzy = str(affected_fuzzy_list[0])
    else:
        # Fallback if 'affected_fuzzy' is not a list or is empty
        self.affected_fuzzy = '1.0.0'


def read_from_json(filename: str,
                   ecosystem_map: DefaultDict[str, Set[str]],
                   bug_map: Dict[str, SimpleBug],
                   package_map: DefaultDict[str, Set[str]]) -> None:
  """Loads bugs from one JSON file into the provided map structures.

  Args:
    filename: The JSON filename to load.
    ecosystem_map: Maps ecosystem names to a set of bug IDs in that ecosystem.
    bug_map: Maps bug IDs to `SimpleBug` objects.
    package_map: Maps package names to a set of bug IDs for that package.
  """
  try:
    with open(filename, "r", encoding='utf-8') as f:
      # json.load can return Any, expect List[Dict[str, Any]] here
      json_data_list: List[Dict[str, Any]] = json.load(f)
      if not isinstance(json_data_list, list):
          logging.warning("JSON file %s does not contain a list of bugs. Skipping.", filename)
          return

      for bug_data_item in json_data_list: # Renamed bug_data
        if not isinstance(bug_data_item, dict) or 'db_id' not in bug_data_item:
            logging.warning("Skipping invalid bug data entry in %s: %s", filename, bug_data_item)
            continue

        simple_bug_instance = SimpleBug(bug_data_item) # Renamed bug
        ecosystem_map[simple_bug_instance.ecosystem].add(simple_bug_instance.db_id)
        package_map[simple_bug_instance.package].add(simple_bug_instance.db_id)
        bug_map[simple_bug_instance.db_id] = simple_bug_instance
  except FileNotFoundError:
    logging.error("Bug data file not found: %s", filename)
  except json.JSONDecodeError:
    logging.error("Error decoding JSON from file: %s", filename)
  except Exception: # Catch any other unexpected errors during file processing
    logging.exception("Unexpected error processing file: %s", filename)


def load_all_bugs() -> Tuple[DefaultDict[str, Set[str]],
                             Dict[str, SimpleBug],
                             DefaultDict[str, Set[str]]]:
  """Loads all bug data from JSON files in the BUG_DIR directory.

  Returns:
    A tuple containing:
      - ecosystem_map: Maps ecosystem names to sets of bug IDs.
      - bug_map: Maps bug IDs to `SimpleBug` objects.
      - package_map: Maps package names to sets of bug IDs.
  """
  ecosystem_data_map: DefaultDict[str, Set[str]] = defaultdict(set) # Renamed
  bug_data_map: Dict[str, SimpleBug] = {} # Renamed
  package_data_map: DefaultDict[str, Set[str]] = defaultdict(set) # Renamed

  if not os.path.isdir(BUG_DIR):
      logging.error("Bug directory not found: %s. Cannot load bug data.", BUG_DIR)
      return ecosystem_data_map, bug_data_map, package_data_map

  for filename_item in os.listdir(BUG_DIR): # Renamed filename
    if filename_item.endswith('.json'):
      full_file_path = os.path.join(BUG_DIR, filename_item) # Renamed file_path
      read_from_json(full_file_path, ecosystem_data_map, bug_data_map, package_data_map)

  logging.info("Loaded %d bugs, %d ecosystems, %d packages from %s",
               len(bug_data_map), len(ecosystem_data_map), len(package_data_map), BUG_DIR)
  return ecosystem_data_map, bug_data_map, package_data_map


async def make_http_request(session: aiohttp.ClientSession,
                            request_url: str,
                            request_type: str, # 'GET' or 'POST'
                            request_body: Optional[Dict[str, Any]] # Body for POST, None for GET
                           ) -> None:
  """Makes one HTTP request using the provided aiohttp session.

  Args:
    session: The aiohttp.ClientSession to use for the request.
    request_url: The URL for the request.
    request_type: The HTTP method ('GET' or 'POST').
    request_body: The JSON body for POST requests (or None for GET).
  """
  try:
    # Define a timeout for the request operations.
    # total: total timeout for whole operation including connection establishment
    # connect: timeout for connection establishment
    # sock_connect: timeout for connecting to a peer (after DNS resolution)
    # sock_read: timeout for reading a portion of data from a peer
    timeout = aiohttp.ClientTimeout(total=None, sock_connect=30.0, sock_read=30.0) # Increased timeout

    if request_type == 'GET':
      # For GET, request_body is not used.
      async with session.get(request_url, timeout=timeout) as response:
        # Optionally, process response status or headers if needed for metrics.
        # For performance testing, often just sending and ensuring it doesn't error out is enough.
        await response.read() # Consume response to free up connection.
    elif request_type == 'POST':
      async with session.post(request_url, json=request_body, timeout=timeout) as response:
        await response.read()
    else:
        logging.error("Unsupported HTTP request type: %s", request_type)

  except asyncio.TimeoutError: # Specifically catch asyncio.TimeoutError from aiohttp
    logging.warning('Timeout sending request %s with body %s', request_url, request_body)
  except aiohttp.ClientError as e: # Catch other aiohttp client errors
    logging.warning('ClientError sending request %s with body %s: %s (%s)',
                    request_url, request_body, type(e).__name__, e)
  except Exception: # Catch any other unexpected errors
    # Log with exc_info=True to get stack trace for unexpected errors.
    logging.exception('Unexpected error sending request %s with body %s', request_url, request_body)


async def make_http_requests_async(
    request_ids: List[str],
    bug_map: Dict[str, SimpleBug],
    url: str,
    batch_size: int,
    payload_func: Callable[..., Optional[Dict[str, Any]]] # Payload func might take ID, bug_map or just IDs
) -> None:
  """Makes HTTP requests asynchronously for a given set of IDs and payload generation function.

  Manages request rate (batch_size per FREQUENCY_IN_SECONDS) over TOTAL_RUNTIME.
  """
  loop_start_time = time.monotonic() # Renamed begin_time
  logging.info('[%s] Starting request loop for %s, target rate: %d reqs/%ds, duration: %ds',
               loop_start_time, payload_func.__name__, batch_size, FREQUENCY_IN_SECONDS, TOTAL_RUNTIME)

  current_run_time: float = 0.0 # Renamed total_run_time
  current_index: int = 0 # Renamed index
  num_request_ids: int = len(request_ids) # Renamed length

  if num_request_ids == 0 and payload_func.__name__ != build_batch_payload.__name__ :
      logging.warning("No request IDs provided for %s. Exiting request loop.", payload_func.__name__)
      return

  # Create a single ClientSession for the duration of this request loop.
  async with aiohttp.ClientSession() as session:
    while current_run_time < TOTAL_RUNTIME:
      iteration_start_time = time.monotonic() # Renamed start_time

      tasks: List[Coroutine[Any, Any, None]] = [] # List to hold asyncio tasks for this batch

      # Determine which type of payload and request structure to use
      if payload_func == build_vulnerability_payload: # Compare functions directly
        # For GetVulnById, generate `batch_size` GET requests using IDs from `request_ids`
        for i in range(batch_size):
          if num_request_ids == 0: break # No IDs to pick from
          actual_request_id = request_ids[current_index % num_request_ids]
          tasks.append(make_http_request(session, f'{url}/{actual_request_id}', 'GET', None))
          current_index +=1
      elif payload_func == build_batch_payload:
        # For QueryBatch, generate `batch_size` POST requests, each with a new batch payload
        for _ in range(batch_size): # Send `batch_size` number of batch queries
            # build_batch_payload itself creates a batch of queries from request_ids and bug_map
            batch_payload = build_batch_payload(request_ids, bug_map) # request_ids is used by build_batch_payload
            tasks.append(make_http_request(session, url, 'POST', batch_payload))
      else: # For other POST queries (package, version, purl)
        for i in range(batch_size):
          if num_request_ids == 0: break
          actual_request_id = request_ids[current_index % num_request_ids]
          # These payload functions expect a single request_id and bug_map
          # The type of payload_func is Callable[..., Optional[Dict[str, Any]]]
          # We need to ensure the arguments match.
          # This dynamic dispatch based on name is fragile.
          # A better way would be to pass arguments structure or use functools.partial.
          # For now, assuming payload_func for these cases takes (request_id, bug_map).
          # This requires payload_func to be compatible with (str, Dict) or (List, Dict)
          # which is not fully captured by the current Callable hint.
          # This implies a more specific Callable type or restructuring.
          # For now, this part is tricky to perfectly type without refactoring payload_func handling.
          # Let's assume payload_func here expects (str, Dict)
          payload = payload_func(actual_request_id, bug_map)
          tasks.append(make_http_request(session, url, 'POST', payload))
          current_index +=1

      if tasks: # If any tasks were created for this iteration
          await asyncio.gather(*tasks) # Run tasks concurrently for this batch

      # Control loop frequency
      iteration_end_time = time.monotonic() # Renamed end_time
      iteration_duration = iteration_end_time - iteration_start_time # Renamed time_elapsed

      sleep_duration = FREQUENCY_IN_SECONDS - iteration_duration
      if sleep_duration > 0:
        await asyncio.sleep(sleep_duration)

      current_run_time = time.monotonic() - loop_start_time

  logging.info("Finished request loop for %s after %.2f seconds.", payload_func.__name__, current_run_time)


def build_vulnerability_payload() -> None: # Returns None, as GET has no body
  """The vulnerability query (GetVulnById) doesn't need a request body."""
  return None


def build_package_payload(request_id: str, bug_map: Dict[str, SimpleBug]) -> Dict[str, Dict[str,str]]:
  """Builds a package query payload (QueryAffected with package but no version)."""
  # bug_map maps bug_id (str) to SimpleBug object
  # Ensure request_id is a valid key in bug_map if this function is called.
  # A check like `if request_id not in bug_map: return {}` might be needed if request_id can be invalid.
  # Assuming request_id is valid and present.
  bug_info = bug_map[request_id]
  return {
      "package": {
          "name": bug_info.package,
          "ecosystem": bug_info.ecosystem
      }
  }


def build_version_payload(request_id: str, bug_map: Dict[str, SimpleBug]) -> Dict[str, Any]:
  """Builds a version query payload (QueryAffected with package and version)."""
  bug_info = bug_map[request_id]
  return {
      "version": bug_info.affected_fuzzy, # This is the version string
      "package": {
          "name": bug_info.package,
          "ecosystem": bug_info.ecosystem
      }
  }


def build_purl_payload(request_id: str, bug_map: Dict[str, SimpleBug]) -> Dict[str, Dict[str, str]]:
  """Builds a PURL query payload (QueryAffected with PURL)."""
  bug_info = bug_map[request_id]
  purl_base: str = bug_info.purl # PURL without version
  # PURL with version appended
  purl_with_version: str = f'{purl_base}@{bug_info.affected_fuzzy}'

  # Randomly choose to send PURL with or without version for query variety
  chosen_purl_str: str = random.choice([purl_base, purl_with_version]) # Renamed

  return {"package": {"purl": chosen_purl_str}}


def build_batch_payload(
    available_request_ids: List[str], # Renamed request_ids to all_available_ids
    bug_map: Dict[str, SimpleBug]
) -> Dict[str, List[Dict[str, Any]]]: # Return type for the batch query body
  """Builds a batch query payload for QueryBatch.

  Randomly selects a number of IDs and constructs individual queries for them.
  """
  # Determine batch size (number of queries within this batch request)
  # Max 100 as per original, min 1.
  num_queries_in_batch: int = random.randint(1, 100) # Renamed size

  # Select a random sample of bug IDs for this batch
  # Ensure available_request_ids is not empty before sampling.
  if not available_request_ids:
      return {"queries": []} # Return empty batch if no IDs to choose from

  # min() handles cases where num_queries_in_batch > len(available_request_ids)
  selected_bug_ids_for_batch: List[str] = random.sample(
      available_request_ids, min(num_queries_in_batch, len(available_request_ids))) # Renamed batch_ids

  individual_queries_list: List[Dict[str, Any]] = [] # Renamed queries
  for bug_id_str in selected_bug_ids_for_batch: # Renamed bug_id
    # For each selected bug_id, randomly choose a query type for it
    query_type_choice: str = random.choice(['version', 'package', 'purl']) # Renamed query_type

    single_query_payload: Dict[str, Any] = {} # Renamed query
    if query_type_choice == 'version':
      single_query_payload = build_version_payload(bug_id_str, bug_map)
    elif query_type_choice == 'package':
      single_query_payload = build_package_payload(bug_id_str, bug_map)
    elif query_type_choice == 'purl':
      single_query_payload = build_purl_payload(bug_id_str, bug_map)

    if single_query_payload: # Ensure a payload was actually built
        individual_queries_list.append(single_query_payload)

  # The final batch request body
  # Original code had `{"queries": [queries]}`, which means a list containing a single list.
  # The proto likely expects `{"queries": List[Query]}`, where `queries` is the list itself.
  # Correcting this to be a flat list of query objects.
  return {"queries": individual_queries_list}


def get_large_batch_query(package_map: DefaultDict[str, Set[str]]) -> List[str]:
  """Gets a list of bug IDs for constructing large batch queries.
  This list includes one bug ID from each of the up to `most_common_packages_limit`
  packages that have the highest number of vulnerabilities.
  """
  most_common_packages_limit = 5000 # Renamed most_common

  # Count vulnerabilities per package
  package_vuln_counter: Counter[str] = Counter() # Renamed
  for package_name_key, bug_ids_set in package_map.items(): # Renamed package
    # Filter out placeholder/invalid package names and potentially very large common ones like "Kernel"
    # if they skew the distribution undesirably for this specific test's goal.
    if package_name_key in ('foo', 'Kernel'): # Assuming 'foo' is a placeholder from SimpleBug defaults
      continue
    package_vuln_counter[package_name_key] = len(bug_ids_set)

  # Get the N most vulnerable packages
  # most_common() returns List[Tuple[str, int]]
  most_vulnerable_pkgs_list: List[Tuple[str, int]] = package_vuln_counter.most_common(most_common_packages_limit) # Renamed

  # Select one bug ID from each of these packages
  # This ensures query diversity across many highly vulnerable packages.
  ids_for_large_batch: List[str] = [] # Renamed large_batch_query_ids
  for package_name_val, vuln_count in most_vulnerable_pkgs_list: # Renamed package, package_count
    if vuln_count == 0: # No bugs in this package (shouldn't happen if it's from package_map keys)
      continue
    # Get the set of bug IDs for this package
    bug_ids_for_package: Optional[Set[str]] = package_map.get(package_name_val)
    if bug_ids_for_package: # If set is not empty
        # Pop an arbitrary bug ID from the set for this package.
        # This also reduces the set in package_map, affecting subsequent calls if package_map is reused.
        # If package_map should not be modified, use `random.sample(list(bug_ids_for_package), 1)[0]`
        # or `next(iter(bug_ids_for_package))`
        ids_for_large_batch.append(bug_ids_for_package.pop())

  random.shuffle(ids_for_large_batch) # Shuffle to vary the order in batches
  return ids_for_large_batch


async def send_version_requests(request_ids: List[str], bug_map: Dict[str, SimpleBug]) -> None:
  """Sends QueryAffected requests by version."""
  url = f'{BASE_URL}/query'
  # Use constant for batch size specific to this request type
  await make_http_requests_async(request_ids, bug_map, url, VERSION_QUERY_BATCH_SIZE,
                                 build_version_payload)


async def send_package_requests(request_ids: List[str], bug_map: Dict[str, SimpleBug]) -> None:
  """Sends QueryAffected requests by package (name and ecosystem)."""
  url = f'{BASE_URL}/query'
  await make_http_requests_async(request_ids, bug_map, url, PACKAGE_QUERY_BATCH_SIZE,
                                 build_package_payload)


async def send_purl_requests(request_ids: List[str], bug_map: Dict[str, SimpleBug]) -> None:
  """Sends QueryAffected requests by PURL."""
  url = f'{BASE_URL}/query'
  await make_http_requests_async(request_ids, bug_map, url, PURL_QUERY_BATCH_SIZE,
                                 build_purl_payload)


async def send_vuln_requests(request_ids: List[str],
                             bug_map: Dict[str, SimpleBug] # bug_map not used by build_vulnerability_payload
                            ) -> None:
  """Sends GetVulnById requests."""
  url = f'{BASE_URL}/vulns'
  # build_vulnerability_payload does not use bug_map, so it can be passed if signature requires it,
  # or signature of make_http_requests_async can be adapted.
  # For now, pass bug_map as it's part of make_http_requests_async signature.
  await make_http_requests_async(request_ids, bug_map, url, VULN_QUERY_BATCH_SIZE,
                                 build_vulnerability_payload)


async def send_batch_requests(request_ids: List[str],
                              bug_map: Dict[str, SimpleBug],
                              current_batch_size: int) -> None: # Renamed batch_size to current_batch_size
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
                          LARGE_BATCH_QUERY_BATCH_SIZE))


if __name__ == "__main__":
  asyncio.run(main())
