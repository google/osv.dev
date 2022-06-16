"""Caches the debian package first version dataframe"""
import gzip
from urllib import request
import json

def load_from_cloud_cache() -> dict[str, dict]:
  """Load the debian version cache from the Google cloud link"""
  res = request.urlopen('https://storage.googleapis.com/debian-osv/first_package_cache.json.gz')
  return json.loads(gzip.decompress(res.read()))


debian_version_cache = load_from_cloud_cache()


def get_first_package_version(package_name: str, release_number: str) -> str:
  """Get first package version"""
  try:
    return debian_version_cache[release_number][package_name]
  except KeyError:
    # The package is not added when the image is first seen.
    # So it is safe to return 0, indicating the earliest version
    # given by the snapshot API
    return '0'


