#!/usr/bin/env python3
"""Utility to delete invalid bugs that match specific criteria.

See https://github.com/google/osv.dev/issues/1098 for additional context.
"""

from google.cloud import datastore
from google.cloud.datastore.query import And, PropertyFilter

import argparse
import sys

MAX_BATCH_SIZE = 500


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Delete bugs that are invalid and match specific criteria.")
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
      "--source_id_prefix",
      action="store",
      dest="source_id_prefix",
      default="",
      help="The prefix of source_id records to delete")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  client = datastore.Client(project=args.project)

  try:
    source = args.source_id_prefix.split(":")[0]
  except IndexError:
    print(f"Unable to determine source from {args.source_id_prefix}")
    sys.exit(1)

  query = client.query(kind="Bug")
  query.add_filter(
      filter=And([
          PropertyFilter("status", "=", 2),
          PropertyFilter("source", "=", source)
      ]))

  print(f"Running query {query.filters} "
        f"on {query.kind} (in {query.project})...")

  result = list(query.fetch())

  print(f"Retrieved {len(result)} bugs to examine for deletion")

  result = list(query.fetch())

  result_to_delete = [
      r for r in result if r['source_id'].startswith(args.source_id_prefix)
  ]

  print(f"There are {len(result_to_delete)} bugs to delete...")

  # Chunk the results to delete in acceptibly sized batches for the API.
  for batch in range(0, len(result_to_delete), MAX_BATCH_SIZE):
    try:
      with client.transaction() as xact:
        for r in result_to_delete[batch:batch + MAX_BATCH_SIZE]:
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
  if len(result_to_delete) > 0 and not args.dryrun:
    print("Deleted!")


if __name__ == "__main__":
  main()
