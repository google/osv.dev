#!/usr/bin/env python3
"""Utility to list the Bug IDs for all of the PROCESSED Bugs in Cloud Datastore.

Cloud Datastore lacks a CLI for issuing queries, and sometimes it's helpful to
reason about all of the Bug IDs present for a given a source.
"""

from google.cloud import datastore
from google.cloud.datastore.query import PropertyFilter

import argparse

MAX_BATCH_SIZE = 500


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Query the identifiers for the Bugs in Datastore "
      "in a PROCESSED state for a given source")
  parser.add_argument(
      "--verbose",
      action=argparse.BooleanOptionalAction,
      dest="verbose",
      default=False,
      help="Be more verbose")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  parser.add_argument(
      "--source_id",
      action="store",
      dest="source_id",
      default="cve-osv",
      help="the source_id to filter on")
  args = parser.parse_args()

  ds_client = datastore.Client(project=args.project)

  query = ds_client.query(kind="Bug")
  query.add_filter(filter=PropertyFilter("source", "=", args.source_id))
  query.add_filter(filter=PropertyFilter("status", "=", 1))
  print(f"Running query {query.filters} "
        f"on {query.kind} (in {query.project})...")
  result = list(query.fetch())
  print(f"Retrieved {len(result)} bugs")

  # Chunk the results to modify in acceptibly sized batches for the API.
  for batch in range(0, len(result), MAX_BATCH_SIZE):
    for bug in result[batch:batch + MAX_BATCH_SIZE]:
      print(f"{bug['db_id']}")


if __name__ == "__main__":
  main()
