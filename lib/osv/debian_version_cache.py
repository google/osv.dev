"""Caches the debian package first version dataframe"""
import gzip
from urllib import request
import json

debian_version_cache = None


def initiate_from_cloud_cache(force_reload: bool = False) -> dict[str, dict]:
  """Load the debian version cache from the Google cloud link, if it hasn't been loaded yet"""
  global debian_version_cache
  if debian_version_cache is None or force_reload:
    res = request.urlopen('https://storage.googleapis.com/debian-osv/first_package_cache.json.gz')
    debian_version_cache = json.loads(gzip.decompress(res.read()))


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""

  if debian_version_cache is None:
    raise Exception("Debian version cache not initiated")

  try:
    return debian_version_cache[release_number][package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to return 0, indicating the earliest version
    # given by the snapshot API
    return '0'


