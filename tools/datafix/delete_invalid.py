#!/usr/bin/env python3
"""Utility to delete invalid bugs that match specific criteria.

See https://github.com/google/osv.dev/issues/1098 for additional context.
"""

from google.cloud import datastore

import argparse
import sys


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

  query = client.query(kind="Bug", filters=(("status", "=", 2),
                                            ("source", "=", source)))

  print(f"Running query {query.filters} "
        f"on {query.kind} (in {query.project})...")

  result = list(query.fetch())

  print(f"Retrieved {len(result)} bugs to examine for deletion")

  result = list(query.fetch())

  result_to_delete = [
      r for r in result if r['source_id'].startswith(args.source_id_prefix)
  ]

  print(f"There are {len(result_to_delete)} bugs to delete...")

  with client.transaction() as xact:
    for r in result_to_delete:
      xact.delete(r.key)
    if args.dryrun:
      raise Exception("Dry run mode. Preventing transaction from commiting")  # pylint: disable=broad-exception-raised
  if len(result_to_delete) > 0:
    print("Deleted!")


if __name__ == "__main__":
  main()
