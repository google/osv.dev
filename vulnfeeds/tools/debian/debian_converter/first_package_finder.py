"""Functions to help find the first package version for a specific release"""
import argparse
import os
import typing
import urllib.error
from datetime import datetime, timedelta
import json
import gzip
from urllib import request

import pandas as pd

DEBIAN_RELEASE_VERSIONS_URL = \
  'https://debian.pages.debian.net/distro-info-data/debian.csv'
DEBIAN_SNAPSHOT_URL = 'https://snapshot.debian.org/archive/debian/{date}/dists/'
# `.gz` format always exist for all snapshots
DEBIAN_SOURCES_URL_EXTENSION = '{version}/main/source/Sources.gz'

# List of ignored versions, mostly too early to be in snapshots
IGNORED_DEBIAN_VERSIONS = frozenset(
    ['experimental', 'buzz', 'rex', 'bo', 'hamm', 'slink', 'potato'])

# Number of days to search (day by day) if the initial date returns 404
FIRST_RELEASE_LOOKAHEAD_DAYS = 10

# First snapshot date for Debian
FIRST_SNAPSHOT_DATE = datetime(2005, 3, 12)

# Prefixes used in the Sources file
PACKAGE_KEY = 'Package: '
VERSION_KEY = 'Version: '


def get_debian_dists_url(date: datetime):
  """Create an url for snapshot.debian.org to get distribution"""
  formatted_date = convert_datetime_to_str_datetime(date)
  return DEBIAN_SNAPSHOT_URL.format(date=formatted_date)


def get_debian_sources_url(date: datetime, version: str):
  """Create an url for snapshot.debian.org"""
  formatted_date = convert_datetime_to_str_datetime(date)

  return DEBIAN_SNAPSHOT_URL.format(
      date=formatted_date) + DEBIAN_SOURCES_URL_EXTENSION.format(
          version=version)


def convert_datetime_to_str_datetime(input_datetime: datetime) -> str:
  """Convert datetime object to debian snapshot url string"""
  return input_datetime.isoformat().replace('-', '').replace(':', '') + 'Z'


def retrieve_codename_to_version() -> pd.DataFrame:
  """Returns the codename to version mapping"""
  with request.urlopen(DEBIAN_RELEASE_VERSIONS_URL) as csv:
    df = pd.read_csv(csv, dtype=str)
    # `series` appears to be `codename` but with no caps
    df['sources'] = ''
    df.dropna(subset=['release'], inplace=True)
    codename_to_version = df.set_index('series')

  return codename_to_version


def parse_created_dates_and_set_time(date: str) -> datetime:
  """Parse created date in debian version csv to datetime plus one day"""
  result = datetime.strptime(date, '%Y-%m-%d') + timedelta(days=1)
  # Set minimum date to first debian snapshot
  return max(result, FIRST_SNAPSHOT_DATE)


def load_sources(date: datetime, dist: str) -> typing.Dict[str, str]:
  """Load the sources file and store in a dictionary of {name: version}"""
  with request.urlopen(get_debian_sources_url(date, dist)) as res:
    decompressed = gzip.decompress(res.read()).decode('iso-8859-2')
    package_version_dict = {}
    current_package = None
    for line in decompressed.splitlines():
      if line.startswith(PACKAGE_KEY):
        current_package = line[len(PACKAGE_KEY):]
        continue

      if line.startswith(VERSION_KEY):
        package_version_dict[current_package] = line[len(VERSION_KEY):]
        continue

    return package_version_dict


def load_first_packages() -> pd.DataFrame:
  """Loads the dataframe containing the first version of packages per distro"""
  codename_to_version: pd.DataFrame = retrieve_codename_to_version()

  first_release_dates = zip(
      codename_to_version.index,
      codename_to_version['release'].map(parse_created_dates_and_set_time))

  first_release_dict: typing.Dict[str, datetime] = dict(
      x for x in first_release_dates if x[0] not in IGNORED_DEBIAN_VERSIONS)

  for version, date in first_release_dict.items():
    # retry for n days into the future if the first request doesn't work
    for i in range(FIRST_RELEASE_LOOKAHEAD_DAYS + 1):
      actual_date = date + timedelta(days=i)
      try:
        codename_to_version.loc[version].sources = load_sources(
            actual_date, version)
        break
      except urllib.error.HTTPError as http_error:
        if http_error.code != 404:
          raise
        # Expect 404 errors for releases before snapshot exists

      if actual_date > datetime.utcnow():
        # No need to keep trying future dates
        break

  return codename_to_version


def get_first_package_version(first_pkg_data: pd.DataFrame, package_name: str,
                              release_name: str) -> str:
  """Get first package version"""
  try:
    return first_pkg_data.loc[release_name].sources[package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to return 0, indicating the earliest version
    # given by the snapshot API
    return '0'


def main():
  parser = argparse.ArgumentParser(description='Detects all first versions')
  parser.add_argument(
      '-o',
      '--output-dir',
      default='first_package_output',
      help='Output folder')
  args = parser.parse_args()

  dataframe = load_first_packages()
  version_to_sources = dict(zip(dataframe['version'], dataframe['sources']))

  os.makedirs(args.output_dir, exist_ok=True)
  for version, sources in version_to_sources.items():
    versions_path = os.path.join(args.output_dir, version + '.json')
    with open(versions_path, 'w') as handle:
      handle.write(json.dumps(sources))


if __name__ == '__main__':
  main()
