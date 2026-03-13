"""Reputs all Bug entities in Datastore.

This is useful for applying changes to all existing entities.
"""

import logging
from multiprocessing import Process
import sys

from google.cloud import ndb

from osv import Bug, gcs

# IDs that divide the OSV database into very roughly equal groups.
# Determined experimentally by print_vuln_ranges
ID_BOUNDS = [
    None,
    'C',
    'CV',
    'CVE-202',
    'CVE-2023',
    'D',
    'DF',
    'G',
    'GHSA-m',
    'H',
    'MAL-2025',
    'MAL-2025-3',
    'MB',
    'Q',
    'S',
    'U',
    'UBUNTU-CVE-202',
    'US',
    None,
]


def iter_bounds():
  """Yields the start and end bounds for each shard."""
  a = ID_BOUNDS[0]
  for b in ID_BOUNDS[1:]:
    yield a, b
    a = b


def print_vuln_ranges():
  """Prints the number of vulnerabilities in each shard.
  
  Useful for re-calculating ID_BOUNDS.
  """
  with ndb.Client().context(cache_policy=False):
    for start, stop in iter_bounds():
      q = Bug.query()
      if start is not None:
        q = q.filter(Bug.key >= ndb.Key('Bug', start))
      if stop is not None:
        q = q.filter(Bug.key < ndb.Key('Bug', stop))
      print(f'[{start}, {stop}): {q.count()}')


def do_reput(start: str | None = None, stop: str | None = None):
  """Re-puts all Bug entities within a given key range."""
  with ndb.Client().context(cache_policy=False):
    q = Bug.query()
    if start:
      q = q.filter(Bug.key >= ndb.Key('Bug', start))
    if stop:
      q = q.filter(Bug.key < ndb.Key('Bug', stop))

    count = 0
    for b in q:
      count += 1
      if count % 500 == 0:
        logging.info('Processed %d entities in shard [%s, %s)', count, start,
                     stop)
      try:
        b.put()
      except Exception as e:
        logging.error('Failed to put %s: %s', b.key.id(), e)


def main():
  """Reputs all bugs in parallel."""
  for a, b in iter_bounds():
    Process(target=do_reput, args=(a, b)).start()


if __name__ == '__main__':
  logging.getLogger().setLevel(logging.INFO)
  try:
    # Make sure the OSV_VULNERABILITIES_BUCKET env is set.
    gcs.get_osv_bucket()
  except:
    sys.exit(1)
  main()
