#!/usr/bin/env python3
"""Utility to mark invalid bugs as withdrawn where they are not currently so.

See https://github.com/google/osv.dev/issues/1098 for additional context.
"""

from google.cloud import datastore

import argparse
import datetime


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Fix bugs that are invalid but not marked as withdrawn")
  parser.add_argument(
      "--dry-run",
      action=argparse.BooleanOptionalAction,
      dest="dryrun",
      default=True,
      help="Abort before making changes")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  client = datastore.Client(project=args.project)

  query = client.query(kind="Bug", filters=(("status", "=", 2),))
  print(f"Running query {query.filters[0]} "
        "on {query.kind} (in {query.project})...")
  result = list(query.fetch())
  print(f"Retrieved {len(result)} bugs to examine for fixing")
  result_to_fix = [r for r in result if not r['withdrawn']]
  print(f"There are {len(result_to_fix)} bugs to fix...")
  with client.transaction() as xact:
    for r in result_to_fix:
      r['withdrawn'] = datetime.datetime.now(tz=datetime.timezone.utc)
      r['last_modified'] = r['withdrawn']
      xact.put(r)
    if args.dryrun:
      raise Exception("Dry run mode. Preventing transaction from commiting")  # pylint: disable=broad-exception-raised
  if len(result_to_fix) > 0:
    print("Fixed!")


if __name__ == "__main__":
  main()
