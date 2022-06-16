"""Caches the debian package first version dataframe"""

import pandas as pd

debian_version_cache = pd.read_pickle(
    'https://storage.googleapis.com/debian-osv/first_package_cache.pickle.gz',
    compression='gzip').set_index('version')


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""
  try:
    return debian_version_cache.loc[release_number].sources[package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to return 0, indicating the earliest version
    # given by the snapshot API
    return '0'
