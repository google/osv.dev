#!/usr/bin/env python3
""" Utility to update the datastore key of each Bug to the new format 
    determined by the pre put hook.

    Does this by deleting and reputting each Bug entry.

    Before running the script, fill out the sections commented with # FILLOUT
"""
from google.cloud import ndb
import osv

import argparse
import json
import time
import typing

MAX_BATCH_SIZE = 500

# Global flags
verbose = False
transform = True


class DryRunException(Exception):
  """This exception is raised to cancel a put during dry runs"""


def get_relevant_ids() -> list[str]:
  """Retrieve the IDs that require refreshing.
  
  1. FILLOUT this function to only return IDs that are necessary to update
  """
  relevant_ids = []

  query = osv.Bug.query()

  # Examples:
  # - Datastore query filters
  # query = query.filter([osv.Bug.source == "ubuntu"])
  #
  # - Apply projections to avoid loading the entire entity
  # query.projection = ["db_id"]
  #
  # - Use a key_only query if no python filtering logic is needed
  query.keys_only = True

  print(f"Running initial query '{ query }' on {query.kind}...")

  result: typing.Iterable[osv.Bug] = query.iter()
  counter = 0

  for res in result:
    counter += 1
    # Check if the key needs to be updated
    relevant_ids.append(res.db_id)
    if verbose:
      print(res.db_id + ' - ' + res.key.id())  # type: ignore

  print(f"Found {len(relevant_ids)} / {counter} relevant bugs to refresh.")
  return relevant_ids


def transform_bug(_: osv.Bug):
  """Transform bug in place.
  
  2. FILLOUT this function to apply transformations before reputting the bug.
  """
  # E.g. Set key to none to regenerate a new key
  # bug.key = None


def refresh_ids(dryrun: bool, loadcache: str) -> None:
  """Update bugs IDs to the new format"""

  relevant_ids = []
  if loadcache:
    with open(loadcache, 'r') as f:
      relevant_ids = json.load(f)
  else:
    relevant_ids = get_relevant_ids()

  # Store the state incase we cancel halfway to avoid having
  # to do the initial query again.
  with open('relevant_ids.json', 'w') as f:
    json.dump(relevant_ids, f)

  num_reputted = 0
  time_start = time.perf_counter()

  # This handles the actual reput of the bugs with ndb
  def _refresh_ids(batch: int):
    buf: list[osv.Bug] = [
        osv.Bug.get_by_id(r) for r in relevant_ids[batch:batch + MAX_BATCH_SIZE]
    ]

    old_keys = {r.key for r in buf}

    if transform:
      # Clear the key so the key name will be regenerated to the new key format
      for elem in buf:
        transform_bug(elem)

    if dryrun:
      print("Dry run mode. Preventing put")
      raise DryRunException

    # Reput the bug back in
    new_keys = set(ndb.put_multi(buf))

    # If the keys have changed, delete the old keys
    # There's a potential for old keys to not get cleaned up if something fails
    if deleted := (old_keys - new_keys):
      ndb.delete_multi(deleted)

    print(f"Time elapsed: {(time.perf_counter() - time_start):.2f} seconds.")

  # Chunk the results to reput in acceptibly sized batches for the API.
  for batch in range(0, len(relevant_ids), MAX_BATCH_SIZE):
    try:
      num_reputted += len(relevant_ids[batch:batch + MAX_BATCH_SIZE])
      print(f"Reput {num_reputted} bugs... - "
            f"{num_reputted/len(relevant_ids)*100:.2f}%")
      _refresh_ids(batch)
    except DryRunException:
      # Don't have the first batch's put-aborting exception stop
      # subsequent batches from being attempted.
      print("Dry run mode. Preventing put")
    except Exception as e:
      print(relevant_ids[batch:batch + MAX_BATCH_SIZE])
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
      "--transform",
      action=argparse.BooleanOptionalAction,
      dest="transform",
      default=True,
      help="Perform transformation code")
  # Add argument for loading from json cache
  parser.add_argument(
      "--load-cache",
      dest="loadcache",
      help="Load the relevant IDs from cache instead of querying")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  global verbose
  global transform

  verbose = args.verbose
  transform = args.transform

  client = ndb.Client(project=args.project)
  print(f"Running on project {args.project}.")
  with client.context():
    refresh_ids(args.dryrun, args.loadcache)


if __name__ == "__main__":
  main()
