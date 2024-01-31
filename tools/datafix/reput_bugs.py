#!/usr/bin/env python3
""" Utility to reput bugs, triggering the Bug _pre_put_hook() in models.py

    This is useful, for example, adding the GIT ecosystem to existing bugs with
    Git ranges.
"""
from google.cloud import ndb
import osv

import argparse

MAX_BATCH_SIZE = 500


def reput_bugs(dryrun: bool, source: str) -> None:
  """ Reput all bugs from a given source."""
  query = osv.Bug.query().filter(osv.Bug.source == source)
  print(f"Running query {query.filters} "
        f"on {query.kind}...")

  result = list(query.fetch(keys_only=True))
  print(f"Retrieved {len(result)} bugs to examine for reputting")

  # This handles the actual transaction of reputting the bugs with ndb
  def _reput_ndb():
    # Reputting the bug runs the Bug _pre_put_hook() in models.py
    print(f"Reputting {len(result[batch:batch + MAX_BATCH_SIZE])} bugs...")
    if dryrun:
      print("Dry run mode. Preventing transaction from commiting")
      raise Exception("Dry run mode")  # pylint: disable=broad-exception-raised

    ndb.put_multi_async([
        osv.Bug.get_by_id(r.id()) for r in result[batch:batch + MAX_BATCH_SIZE]
    ])

  # Chunk the results to reput in acceptibly sized batches for the API.
  for batch in range(0, len(result), MAX_BATCH_SIZE):
    try:
      ndb.transaction(_reput_ndb)
    except Exception as e:
      # Don't have the first batch's transaction-aborting exception stop
      # subsequent batches from being attempted.
      if dryrun and e.args[0].startswith("Dry run mode"):
        print("Dry run mode. Preventing transaction from commiting")
      else:
        print(f"Exception {e} occurred. Continuing to next batch.")

  print("Reputted!")


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

  client = ndb.Client(project=args.project)
  with client.context():
    reput_bugs(args.dryrun, args.source)


if __name__ == "__main__":
  main()
