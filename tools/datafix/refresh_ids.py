#!/usr/bin/env python3
""" Utility to update the datastore key of each Bug to the new format determined by the pre put hook.

    Does this by deleting and reputting each Bug entry.
"""
from google.cloud import ndb
import osv

import argparse
import json
import functools
import time
import typing

MAX_BATCH_SIZE = 500


class DryRunException(Exception):
  """This exception is raised to cancel a transaction during dry runs"""


def get_relevant_ids(verbose: bool) -> list[str]:
  relevant_ids = []

  query = osv.Bug.query()
  query.projection = ["db_id"]
  print(f"Running initial query on {query.kind}...")

  result: typing.Iterable[osv.Bug] = query.iter()
  counter = 0

  for res in result:
    counter += 1
    # Check if the key needs to be updated
    if res.key.id() != res.db_id:  # type: ignore
      relevant_ids.append(res.db_id)
      if verbose:
        print(res.db_id + ' - ' + res.key.id())  # type: ignore

  print(f"Found {len(relevant_ids)} / {counter} relevant bugs to refresh.")
  return relevant_ids


def reput_bugs(dryrun: bool, verbose: bool) -> None:
  """ Reput all bugs from a given source."""

  relevant_ids = []
  # Uncomment below to load the state and skip the get_relevant_ids func
  # with open('relevant_ids.json', 'r') as f:
  #   relevant_ids = json.load(open('relevant_ids.json', 'r'))
  relevant_ids = get_relevant_ids(verbose)

  # Store the state incase we cancel halfway to avoid having to do the initial query again
  with open('relevant_ids.json', 'w') as f:
    json.dump(relevant_ids, f)

  num_reputted = 0
  time_start = time.perf_counter()

  # This handles the actual transaction of reputting the bugs with ndb
  def _reput_ndb(batch: int):
    buf: list[osv.Bug] = [
        osv.Bug.get_by_id(r) for r in relevant_ids[batch:batch + MAX_BATCH_SIZE]
    ]

    # Delete the existing entries. This must be done in a transaction to avoid losing data if interrupted
    ndb.delete_multi([r.key for r in buf])

    # Clear the key so the key name will be regenerated to the new key format
    for i in range(len(buf)):
      buf[i].key = None

    # Reput the bug back in
    ndb.put_multi_async(buf)

    if dryrun:
      print("Dry run mode. Preventing transaction from committing")
      raise DryRunException

    print(f"Time elapsed: {(time.perf_counter() - time_start):.2f} seconds.")

  # Chunk the results to reput in acceptibly sized batches for the API.
  for batch in range(0, len(relevant_ids), MAX_BATCH_SIZE):
    try:
      num_reputted += len(relevant_ids[batch:batch + MAX_BATCH_SIZE])
      print(
          f"Reput {num_reputted} bugs... - {num_reputted/len(relevant_ids)*100:.2f}%"
      )
      ndb.transaction(functools.partial(_reput_ndb, batch))
    except DryRunException:
      # Don't have the first batch's transaction-aborting exception stop
      # subsequent batches from being attempted.
      print("Dry run mode. Preventing transaction from committing")
    except Exception as e:
      print([r for r in relevant_ids[batch:batch + MAX_BATCH_SIZE]])
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
      "--verbose",
      action=argparse.BooleanOptionalAction,
      dest="verbose",
      default=False,
      help="Print each ID that needs to be processed")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  client = ndb.Client(project=args.project)
  print(f"Running on project {args.project}.")
  with client.context():
    reput_bugs(args.dryrun, args.verbose)


if __name__ == "__main__":
  main()
