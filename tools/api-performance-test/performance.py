#!/usr/bin/env python3
"""Mock API queries and send them to the test API endpoint
for performance testing."""

import asyncio
import os
import random
import time
import aiohttp
import json

from google.cloud import ndb
import osv

from collections import Counter, defaultdict

BASE_URL = 'https://api.test.osv.dev/v1'
TOTAL_RUNTIME = 3600  # total run time in second
GCP_PROJECT = 'oss-vdb-test'
BUG_DIR = './all_bugs'

# Number of vulnerability get requests to send per second
VULN_QUERY_BATCH_SIZE = 100
VERSION_QUERY_BATCH_SIZE = 200
PACKAGE_QUERY_BATCH_SIZE = 60
BATCH_QUERY_BATCH_SIZE = 6
LARGE_BATCH_QUERY_BATCH_SIZE = 4


class SimpleBug:
  """A simplified bug only contains essential information
  for making HTTP requests."""

  def __init__(self, bug_dict):
    self.db_id = bug_dict['db_id']
    # If the project/ecosystem/version value is None, then add a fake value in.
    if not bug_dict['project']:
      self.projects = 'foo'
    else:
      self.projects = list(bug_dict['project'])
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


def format_bug_for_output(bug):
  """Outputs ndb bug query results to JSON file"""
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


def get_bugs_from_datastore():
  """Gets all bugs from the datastore and write them to separate files in case
  the query fails or times out."""

  entries_per_file = 10000  # amount of bugs per file
  batch_size = 1000
  file_counter = 0
  os.makedirs(BUG_DIR, exist_ok=True)

  def write_to_json():
    # Write to a new JSON file
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


def read_from_json(filename, ecosystem_map, bug_map, project_map):
  """Reads one JSON file"""
  with open(filename, "r") as f:
    json_file = json.load(f)
    for bug_data in json_file:
      bug = SimpleBug(bug_data)
      for ecosystem in bug.ecosystems:
        ecosystem_map[ecosystem].add(bug.db_id)
      for project in bug.projects:
        project_map[project].add(bug.db_id)
      bug_map[bug.db_id] = bug


def load_all_bugs(directory_path):
  """Loads bugs from JSON output"""
  ecosystem_map = defaultdict(set)
  bug_map = {}
  project_map = defaultdict(set)
  for filename in os.listdir(directory_path):
    if filename.endswith('.json'):
      file_path = os.path.join(directory_path, filename)
      read_from_json(file_path, ecosystem_map, bug_map, project_map)
  return ecosystem_map, bug_map, project_map


async def make_http_request(session, request_url, request_type, request_body):
  """Makes one HTTP request"""
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


async def make_http_requests_async(request_ids, bug_map, url, batch_size,
                                   payload_func):
  """Makes the required number of HTTP requests per second."""
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
      if payload_func.__name__ == vulnerability_payload.__name__:
        for request_id in batch_request_ids:
          asyncio.create_task(
              make_http_request(session, f'{url}/{request_id}', 'GET',
                                payload_func()))
      elif payload_func.__name__ == batch_payload.__name__:
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
      if time_elapsed < 1:
        await asyncio.sleep(1 - time_elapsed)
      total_run_time = time.monotonic() - begin_time


def package_payload(request_id, bug_map):
  """package/project query payload"""
  package = random.choice(bug_map[request_id].projects)
  ecosystem = random.choice(bug_map[request_id].ecosystems)
  return {"package": {"name": package, "ecosystem": ecosystem}}


def version_payload(request_id, bug_map):
  """version query payload"""
  package = random.choice(bug_map[request_id].projects)
  ecosystem = random.choice(bug_map[request_id].ecosystems)
  return {
      "version": bug_map[request_id].affected_fuzzy,
      "package": {
          "name": package,
          "ecosystem": ecosystem
      }
  }


def batch_payload(request_ids, bug_map):
  """batch query payload"""
  size = random.randint(1, 100)
  batch_ids = random.sample(request_ids, min(size, len(request_ids)))
  queries = []
  for bug_id in batch_ids:
    query = {}
    query_type = random.choice(['version', 'project'])
    if query_type == 'version':
      query = version_payload(bug_id, bug_map)
    elif query_type == 'project':
      query = package_payload(bug_id, bug_map)
    queries.append(query)

  return {"queries": [queries]}


def vulnerability_payload():
  """vulnerability query doesn't need request body"""
  return None


def get_large_batch_query(project_map):
  """Gets packages with the most amount of vulns."""
  most_common = 5000
  project_counter = Counter()
  for project in project_map:
    # filter out invalid project name and Linux Kernel
    if project in ('foo', 'Kernel'):
      continue
    project_counter[project] = len(project_map[project])
  most_vulnerable_projects = project_counter.most_common(most_common)
  large_batch_query_ids = []
  for project, project_count in most_vulnerable_projects:
    if project_count == 10:
      break
    large_batch_query_ids.append(project_map[project].pop())

  random.shuffle(large_batch_query_ids)
  return large_batch_query_ids


async def send_version_requests(request_ids, bug_map):
  """Sends version query requests"""
  url = f'{BASE_URL}/query'
  batch_size = VERSION_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 version_payload)


async def send_package_requests(request_ids, bug_map):
  """Sends package query requests"""
  url = f'{BASE_URL}/query'
  batch_size = PACKAGE_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 package_payload)


async def send_vuln_requests(request_ids, bug_map):
  """Sends vulnerability get requests"""
  url = f'{BASE_URL}/vulns'
  batch_size = VULN_QUERY_BATCH_SIZE
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 vulnerability_payload)


async def send_batch_requests(request_ids, bug_map, batch_size):
  """Sends batch query requests"""
  url = f'{BASE_URL}/querybatch'
  await make_http_requests_async(request_ids, bug_map, url, batch_size,
                                 batch_payload)


async def main():
  """Main"""
  if not os.path.exists(BUG_DIR):
    # This will take around 10 mins
    get_bugs_from_datastore()

  # The `ecosystem_map` can be used to filter our queries for a
  # specific ecosystem.
  ecosystem_map, bug_map, project_map = load_all_bugs(BUG_DIR)
  vuln_query_ids = list(bug_map.keys())
  package_query_ids = []
  for project in project_map:
    # Tests each project once.
    package_query_ids.append(project_map[project].pop())
  random.shuffle(package_query_ids)
  random.shuffle(vuln_query_ids)
  print(f'It will send vulnerability get requests for {len(vuln_query_ids)} '
        'vulnerabilities.')
  print('It will send package/version/batch query requests for '
        f'{len(package_query_ids)} projects within '
        f'{len(ecosystem_map)} ecosystems.')

  # Get all projects with the most frequently occurring number
  # of vulnerabilities.
  large_batch_query_ids = get_large_batch_query(project_map)

  await asyncio.gather(
      send_vuln_requests(vuln_query_ids, bug_map),
      send_package_requests(package_query_ids, bug_map),
      send_version_requests(package_query_ids, bug_map),
      send_batch_requests(package_query_ids, bug_map, BATCH_QUERY_BATCH_SIZE),
      send_batch_requests(large_batch_query_ids, bug_map,
                          LARGE_BATCH_QUERY_BATCH_SIZE))


if __name__ == "__main__":
  asyncio.run(main())
