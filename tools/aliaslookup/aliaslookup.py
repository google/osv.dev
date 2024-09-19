#!/usr/bin/env python3
"""Utility to look up OSV records by alias.
"""

from google.cloud import datastore

import sys
import fileinput
import argparse


def lookup_by_aliases(client: datastore.Client,
                      identifiers: list[str],
                      verbose=False) -> datastore.query.Iterator:
  """Look up OSV records by alias.

  Args:
    client: a datastore.Client object.
    identifiers: a list of strings being the aliases to look up.
    verbose: a boolean whether to emit more verbose processing information.

  Returns:
    a datastore.query.Iterator
  """
  for identifier in identifiers:
    query = client.query(kind='Bug')
    query.add_filter(
        filter=datastore.query.PropertyFilter('aliases', 'IN', [identifier]))
    if verbose:
      print(f'Running query {query.filters[0]} '
            f'on {query.kind} (in {query.project})...')
    result = list(query.fetch())
    if verbose:
      print(f'Retrieved {len(result)} bugs')

    if len(result) > 0:
      yield result[0]
    else:
      continue


def main() -> None:
  parser = argparse.ArgumentParser(description='Look up OSV records by alias')
  parser.add_argument(
      '--aliases',
      action='store',
      dest='aliases',
      help='comma-separated list of IDs to look up')
  parser.add_argument(
      '--filename',
      action='store',
      dest='filename',
      help='Filename of newline-separated IDs to look up')
  parser.add_argument(
      '--project',
      action='store',
      dest='project',
      default='oss-vdb-test',
      help='GCP project to operate on')
  parser.add_argument(
      '--verbose',
      action=argparse.BooleanOptionalAction,
      dest='verbose',
      default=False,
      help='Be more verbose')

  args = parser.parse_args()

  client = datastore.Client(project=args.project)

  aliases = []
  bugs = []

  if not args.aliases and not args.filename:
    if sys.stdin.isatty():
      print('Reading newline separated IDs from STDIN...')
    for alias in sys.stdin:
      aliases.append(alias.strip())

  if args.aliases:
    aliases = args.aliases.split(",")

  if args.filename:
    with fileinput.input(files=args.filename) as f:
      for alias in f:
        aliases.append(alias.strip())

  if aliases:
    bugs = lookup_by_aliases(client, aliases, args.verbose)

  if bugs:
    print('alias,bug')
    for bug in bugs:
      for alias in set(bug['aliases']).intersection(set(aliases)):
        print(f'{alias},{bug["db_id"]}')


if __name__ == "__main__":
  main()
