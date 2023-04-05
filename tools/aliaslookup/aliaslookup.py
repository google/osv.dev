#!/usr/bin/env python3
"""Utility to look up OSV records by alias.
"""

from google.cloud import datastore

import sys
import fileinput
import argparse


def LookupByAliases(client: datastore.Client,
                    identifiers: list[str],
                    verbose=False) -> str:
  query = client.query(kind="Bug")
  query.add_filter(
      filter=datastore.query.PropertyFilter("aliases", "IN", identifiers))
  if verbose:
    print(f"Running query {query.filters[0]} "
          f"on {query.kind} (in {query.project})...")
  result = list(query.fetch())
  if verbose:
    print(f"Retrieved {len(result)} bugs")

  if result:
    return result


def main() -> None:
  parser = argparse.ArgumentParser(description="Look up OSV records by alias")
  parser.add_argument(
      "--aliases",
      action="store",
      dest="aliases",
      help="comma-separated list of IDs to look up")
  parser.add_argument(
      "--filename",
      action="store",
      dest="filename",
      help="Filename of newline-separated IDs to look up")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  parser.add_argument(
      "--verbose",
      action=argparse.BooleanOptionalAction,
      dest="verbose",
      default=False,
      help="Be more verbose")

  args = parser.parse_args()

  client = datastore.Client(project=args.project)

  aliases = list()
  bugs = list()

  if not args.aliases and not args.filename:
    if sys.stdin.isatty():
      print("Reading newline separated IDs from STDIN...")
    for alias in sys.stdin:
      aliases.append(alias.strip())

  if args.aliases:
    aliases = args.aliases.split(",")

  if args.filename:
    with fileinput.input(files=args.filename) as f:
      for alias in f:
        aliases.append(alias)

  if aliases:
    bugs = LookupByAliases(client, aliases, args.verbose)

  if bugs:
    print("aliases,bug")
    for bug in bugs:
      print(f"{bug['aliases'][0]},{bug['db_id']}")


if __name__ == "__main__":
  main()
