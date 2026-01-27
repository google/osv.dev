#!/usr/bin/env python3
"""Utility to delete all bugs for a given source or from a given file."""

import sys
from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter

import argparse

MAX_BATCH_SIZE = 500


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Delete all bugs from a given source.")
  parser.add_argument(
      "--dry-run",
      action=argparse.BooleanOptionalAction,
      dest="dryrun",
      default=True,
      help="Abort before making changes")
  parser.add_argument(
      "--verbose",
      action=argparse.BooleanOptionalAction,
      dest="verbose",
      default=False,
      help="Display records being operated on")
  parser.add_argument(
      "--source",
      action="store",
      dest="source",
      default="cve-osv",
      help="The prefix of source_id records to delete")
  parser.add_argument(
      "--delete_from_file",
      action=argparse.BooleanOptionalAction,
      dest="delete_from_file",
      default=False,
      help="Delete individual bugs from a file")
  parser.add_argument(
      "--file",
      action="store",
      dest="file",
      default="",
      help="The file path of bug ids to delete")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  client = datastore.Client(project=args.project)

  result = []
  if args.delete_from_file:
    delete_from_file(client, args.file, args.verbose, args.dryrun)
    return

  query = client.query(kind="Bug")
  query.add_filter(filter=PropertyFilter("source", "=", args.source))

  if not args.verbose:
    query.keys_only()

  print(f"Running query {query.filters} "
        f"on {query.kind} (in {query.project})...")

  result = list(query.fetch())

  print(f"There are {len(result)} bugs to delete...")

  # Chunk the results to delete in acceptibly sized batches for the API.
  for batch in range(0, len(result), MAX_BATCH_SIZE):
    try:
      with client.transaction() as xact:
        for r in result[batch:batch + MAX_BATCH_SIZE]:
          if args.verbose:
            print(f"Deleting {r}")
          xact.delete(r.key)
        if args.dryrun:
          raise Exception("Dry run mode. Preventing transaction from commiting")  # pylint: disable=broad-exception-raised
    except Exception as e:
      # Don't have the first batch's transaction-aborting exception stop
      # subsequent batches from being attempted.
      if args.dryrun and e.args[0].startswith("Dry run mode"):
        pass
      else:
        raise
  if len(result) > 0 and not args.dryrun:
    print("Deleted!")


def delete_from_file(client: datastore.Client, filepath, verbose, dry_run):
  """Delete bugs from a file"""
  ids = []
  kind = "Bug"
  try:
    with open(filepath, 'r') as file:
      ids = [bug.rstrip() for bug in file]
      print(f"There are {len(ids)} bugs to delete...")
  except Exception as e:
    print('ERROR: Please provide an valid bug file,'
          f'separating each id with a new line. Error: {e}')
    sys.exit(1)

  for batch_start in range(0, len(ids), MAX_BATCH_SIZE):
    batch_end = batch_start + MAX_BATCH_SIZE
    batch_ids = ids[batch_start:batch_end]

    try:
      with client.transaction() as xact:
        for db_id in batch_ids:
          key = client.key(kind, db_id)
          if verbose:
            print(f"Deleting {key}")
          if not dry_run:
            xact.delete(key)
          else:
            print("Dry run mode. Preventing transaction from committing")
    except Exception as e:
      print(f"Error during batch delete: {e}")
  if len(ids) > 0 and not dry_run:
    print("Deleted!")


if __name__ == "__main__":
  main()
