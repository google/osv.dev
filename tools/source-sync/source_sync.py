"""Download all of the records from one or all of the defined OSV.dev sources"""

import os
import argparse
import yaml
import json
import pprint
import urllib
import concurrent.futures
from urllib3.util.retry import Retry
import requests
from requests.adapters import HTTPAdapter
import re
import pygit2
from google.cloud import storage
from google.cloud.storage import retry


class Error(Exception):
  """General purpose exception for errors."""


def Sources(source_path: str) -> dict:
  """Return a dictionary of the contents of a source.yaml file."""
  return yaml.safe_load(open(source_path))


def DownloadSource(source: dict, directory: str, verbose: bool = False) -> None:
  """Download the source defined in the dictionary."""
  if verbose:
    print(f'Operating on: {pprint.pformat(source)}')
  if source['type'] == 0:
    DownloadGitSource(source, directory, verbose)
    return
  if source['type'] == 1:
    DownloadGCSSource(source, directory, verbose)
    return
  if source['type'] == 2:
    DownloadRESTSource(source, directory, verbose)
    return
  raise Error(f'Unexpected source type: {source["type"]=}')


def DownloadGitSource(source: dict,
                      directory: str,
                      verbose: bool = False) -> None:
  """(Shallow) clone a Git-based source."""
  path = os.path.join(directory, source['name'])
  if verbose:
    print(f'[{source["name"]}]: Cloning {source["repo_url"]} into {path}')
  _ = pygit2.clone_repository(
      source['repo_url'],
      path,
      checkout_branch=source.get('repo_branch', None),
      depth=1)


def DownloadGCSSource(source: dict,
                      directory: str,
                      verbose: bool = False) -> None:
  """Download the files from a GCS-based source."""
  storage_client = storage.Client()
  # List all the blobs in the bucket.
  blobs = list(
      storage_client.list_blobs(
          source['bucket'],
          prefix=source.get('directory_path', None),
          retry=retry.DEFAULT_RETRY))
  if 'extension' in source:
    # Filter by file extension.
    blobs = [blob for blob in blobs if blob.path.endswith(source['extension'])]
  if 'ignore_patterns' in source:
    # Filter by ignore pattern(s).
    blobs = [
        blob for blob in blobs if not any(
            re.match(pattern, os.path.basename(urllib.parse.unquote(blob.path)))
            for pattern in source['ignore_patterns'])
    ]
  os.makedirs(os.path.join(directory, source['name']), exist_ok=True)
  for blob in blobs:
    # Clear the blob's generation for more reliable downloading.
    blob = storage.Blob(blob.name, blob.bucket, generation=None)
    if verbose:
      print(f'[{source["name"]}]: Downloading {blob}')
    fn = os.path.join(directory, source['name'],
                      os.path.basename(urllib.parse.unquote(blob.path)))
    blob.download_to_filename(fn, retry=retry.DEFAULT_RETRY)


def GetWithRetry(url, timeout=None, retries=3):
  """Retry HTTP GET with backoff."""
  adapter = HTTPAdapter(
      max_retries=Retry(
          total=retries,
          backoff_factor=1,
          status_forcelist=[429, 500, 502, 503, 504],
          allowed_methods=['HEAD', 'GET', 'OPTIONS']))
  http = requests.Session()
  http.mount('https://', adapter)
  http.mount('http://', adapter)

  response = http.get(url, timeout=timeout)
  response.raise_for_status()
  return response


def DownloadRESTSource(source: dict,
                       directory: str,
                       verbose: bool = False) -> None:
  """Download from a REST API-based source."""
  os.makedirs(os.path.join(directory, source['name']), exist_ok=True)
  r = requests.get(source['rest_api_url'], timeout=30)
  for record in r.json():
    fn = os.path.join(directory, source['name'],
                      record['id'] + source['extension'])
    if record.keys() == {'id', 'modified'}:
      # Minimalist record, request the full one individually.
      record_url = source['link'] + record['id'] + source['extension']
      r = GetWithRetry(record_url, timeout=30, retries=3)
      with open(fn, mode='w') as record_f:
        if verbose:
          print(
              f'[{source["name"]}]: Writing {record["id"]} to {record_f.name}')
        record_f.write(r.text)
    else:
      # The full record was supplied in the initial listing.
      with open(fn, mode='w') as record_f:
        if verbose:
          print(
              f'[{source["name"]}]: Writing {record["id"]} to {record_f.name}')
        json.dump(record, record_f)


def main() -> None:
  parser = argparse.ArgumentParser(
      description='Download records from an OSV.dev data source.')
  parser.add_argument(
      '--verbose',
      action=argparse.BooleanOptionalAction,
      dest='verbose',
      default=False,
      help='Print verbose output')
  parser.add_argument(
      '--source_file',
      action='store',
      dest='source_file',
      default='../../source.yaml',
      help='The YAML file describing the OSV.dev sources')
  parser.add_argument(
      '--directory',
      action='store',
      dest='directory',
      default='/tmp',
      help='The directory to download the records to')
  parser.add_argument(
      '--list',
      action='store_true',
      dest='list',
      default=False,
      help='List the available sources to use with --source')
  parser.add_argument(
      '--source',
      action='store',
      dest='source',
      default='',
      nargs='+',
      help='The source to download (or "ALL")')
  parser.add_argument(
      '--source_exclude',
      action='store',
      dest='source_exclude',
      default='',
      nargs='+',
      help='The sources to exclude from downloading when using "--source ALL")')
  args = parser.parse_args()

  if not args.list and not args.source:
    parser.error('either --list or --source are required')

  if args.source_exclude and args.source != ['ALL']:
    parser.error('useless use of "--source_exclude" without "--source ALL"')

  sources = Sources(args.source_file)

  if args.list:
    print('Available sources:\n')
    for source in sources:
      print(f'\t{source["name"]}')
    return

  with concurrent.futures.ThreadPoolExecutor() as executor:
    future_to_source = {
        executor.submit(DownloadSource, source, args.directory, args.verbose):
            source for source in sources if source['name'] in args.source or
        (args.source == ['ALL'] and source['name'] not in args.source_exclude)
    }
    for future in concurrent.futures.as_completed(future_to_source):
      inflight = [
          source['name']
          for (f, source) in future_to_source.items()
          if f.running()
      ]
      print(f'Still in flight: {pprint.pformat(inflight, width=1)}')
      source = future_to_source[future]
      if exc := future.exception():
        print(f"source['name'] raised {exc}")
      else:
        print(f"{source['name']} completed")


if __name__ == '__main__':
  main()
