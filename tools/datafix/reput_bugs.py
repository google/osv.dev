#!/usr/bin/env python3
""" Utility to reput bugs, triggering the Bug _pre_put_hook() in models.py

    This is useful, for example, adding the GIT ecosystem to existing bugs with
    Git ranges.
"""
from google.cloud import ndb
import osv
import time

import argparse

MAX_BATCH_SIZE = 500


def reput_bugs(dryrun: bool, source: str, ids: list) -> None:
  """ Reput all bugs from a given source."""
  query = osv.Bug.query()
  if ids:
    result = [ndb.Key(query.kind, id) for id in ids[0]]
  else:
    query = query.filter(osv.Bug.source == source)
    print(f"Running query {query.filters} "
          f"on {query.kind}...")
    result = list(query.fetch(keys_only=True))

  result.sort(key=lambda r: r.id())
  # result = [r for r in result if not r.id()[0].isnumeric()]
  print(f"Retrieved {len(result)} bugs to examine for reputting")
  num_reputted = 0
  time_start = time.perf_counter()

  # This handles the actual transaction of reputting the bugs with ndb
  def _reput_ndb():
    # Reputting the bug runs the Bug _pre_put_hook() in models.py
    if dryrun:
      print("Dry run mode. Preventing transaction from commiting")
      raise Exception("Dry run mode")  # pylint: disable=broad-exception-raised
    ndb.put_multi_async([
        osv.Bug.get_by_id(r.id()) for r in result[batch:batch + MAX_BATCH_SIZE]
    ])
    print(f"Time elapsed: {(time.perf_counter() - time_start):.2f} seconds.")

  # Chunk the results to reput in acceptibly sized batches for the API.
  for batch in range(0, len(result), MAX_BATCH_SIZE):
    try:
      num_reputted += len(result[batch:batch + MAX_BATCH_SIZE])
      print(
          f"Reput {num_reputted} bugs... - {num_reputted/len(result)*100:.2f}%")
      ndb.transaction(_reput_ndb)
    except Exception as e:
      # Don't have the first batch's transaction-aborting exception stop
      # subsequent batches from being attempted.
      if dryrun and e.args[0].startswith("Dry run mode"):
        print("Dry run mode. Preventing transaction from commiting")
      else:
        print([r.id() for r in result[batch:batch + MAX_BATCH_SIZE]])
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
  parser.add_argument(
      "--bugs",
      action="append",
      nargs="+",
      required=False,
      help=f"The bug IDs to operate on ({MAX_BATCH_SIZE} at most)")
  args = parser.parse_args()

  client = ndb.Client(project=args.project)
  with client.context():
    reput_bugs(args.dryrun, args.source, args.bugs)


if __name__ == "__main__":
  main()
