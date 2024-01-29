#!/usr/bin/env python3
""" Utility to reput bugs so that those with git ranges 
    are classified with the GIT ecosystem. """

from google.cloud import datastore

from google.cloud import ndb
import osv
from google.cloud.datastore.query import PropertyFilter

import argparse

ndb_client = None
MAX_BATCH_SIZE = 500


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Reput all bugs from a given source.")
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
      default="curl",
      help="The prefix of source_id records to reput")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  client = datastore.Client(project=args.project)

  query = client.query(kind="Bug")
  query.add_filter(filter=PropertyFilter("source", "=", args.source))
  if not args.verbose:
    query.keys_only()

  print(f"Running query {query.filters} "
        f"on {query.kind} (in {query.project})...")

  result = list(query.fetch())

  print(f"Retrieved {len(result)} bugs to examine for reputting")

  # Chunk the results to reput in acceptibly sized batches for the API.
  for batch in range(0, len(result), MAX_BATCH_SIZE):
    try:
      with client.transaction():
        # Reputting the bug runs the Bug _pre_put_hook() in models.py
        # which will give the bug the 'GIT' ecosystem if it has a git range.
        ndb.put_multi_async([
            osv.Bug.get_by_id(r.key.name)
            for r in result[batch:batch + MAX_BATCH_SIZE]
        ])
        print(f"Reputting {len(result[batch:batch + MAX_BATCH_SIZE])} bugs...")
        if args.dryrun:
          raise Exception("Dry run mode. Preventing transaction from commiting")  # pylint: disable=broad-exception-raised
    except Exception as e:
      # Don't have the first batch's transaction-aborting exception stop
      # subsequent batches from being attempted.
      if args.dryrun and e.args[0].startswith("Dry run mode"):
        pass
  print("Reputted!")


if __name__ == "__main__":
  ndb_client = ndb.Client(project='oss-vdb-test')
  with ndb_client.context() as context:
    main()
