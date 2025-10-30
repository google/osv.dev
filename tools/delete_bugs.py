#!/usr/bin/env python3
"""Utility to delete Bug entities from Datastore.

Features:
- Delete by source prefix (query) or from a newline-separated file of IDs.
- Safe dry-run mode (default) that prints what WOULD be deleted.
- Batched deletes (MAX_BATCH_SIZE) to avoid API limits.
- Verbose logging option.
- Clear error handling.

Usage examples:
  # Dry run: show what would be deleted for source "cve-osv"
  python3 tools/delete_bugs.py --source cve-osv

  # Actually delete
  python3 tools/delete_bugs.py --source cve-osv --no-dry-run --project my-gcp-project

  # Delete IDs from file (one id per line)
  python3 tools/delete_bugs.py --delete-from-file --file /path/to/ids.txt --no-dry-run
"""

from __future__ import annotations

import argparse
import sys
from typing import List

from google.cloud import datastore

MAX_BATCH_SIZE = 500


def parse_args() -> argparse.Namespace:
  parser = argparse.ArgumentParser(
      description="Delete Bug entities from Google Cloud Datastore.")
  parser.add_argument(
      "--dry-run",
      action=argparse.BooleanOptionalAction,
      dest="dryrun",
      default=True,
      help="If enabled (default), do not perform deletions; only print what would be deleted.")
  parser.add_argument(
      "--verbose",
      action=argparse.BooleanOptionalAction,
      dest="verbose",
      default=False,
      help="If enabled, print detailed records / keys.")
  parser.add_argument(
      "--source",
      action="store",
      dest="source",
      default="cve-osv",
      help="The prefix or exact value of Bug.source to delete (used for query).")
  parser.add_argument(
      "--delete-from-file",
      action=argparse.BooleanOptionalAction,
      dest="delete_from_file",
      default=False,
      help="If enabled, delete bug entities whose IDs are listed in --file.")
  parser.add_argument(
      "--file",
      action="store",
      dest="file",
      default="",
      help="Path to newline-separated file containing bug IDs to delete.")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on.")
  return parser.parse_args()


def delete_by_source(client: datastore.Client, source: str, verbose: bool, dry_run: bool) -> None:
  """Delete all Bug entities where the 'source' property equals the given source."""
  query = client.query(kind="Bug")
  # Use equality filter for source. If you want prefix-match, implement it separately.
  query.add_filter("source", "=", source)

  if not verbose:
    query.keys_only()

  print(f"Running query filter: source == '{source}' on kind=Bug (project={client.project})...")
  entities = list(query.fetch())

  total = len(entities)
  print(f"Found {total} bug(s) matching source='{source}'.")

  if total == 0:
    return

  # Convert results to keys (if keys_only wasn't used)
  keys: List[datastore.Key] = [e.key if hasattr(e, "key") else e for e in entities]

  for start in range(0, total, MAX_BATCH_SIZE):
    batch_keys = keys[start:start + MAX_BATCH_SIZE]
    if verbose:
      for k in batch_keys:
        print(f"{'Would delete' if dry_run else 'Deleting'}: {k}")
    else:
      print(f"{'Would delete' if dry_run else 'Deleting'} batch {start // MAX_BATCH_SIZE + 1} "
            f"({len(batch_keys)} keys)")

    if not dry_run:
      try:
        client.delete_multi(batch_keys)
      except Exception as exc:  # Keep this broad for visibility; callers can re-run if needed.
        print(f"Error deleting batch starting at index {start}: {exc}")
        raise

  if not dry_run:
    print("Delete operation completed.")
  else:
    print("Dry-run mode enabled; no entities were deleted.")


def delete_from_file(client: datastore.Client, filepath: str, verbose: bool, dry_run: bool) -> None:
  """Delete bugs by their datastore IDs listed in a file (one id per line)."""
  kind = "Bug"
  try:
    with open(filepath, "r", encoding="utf-8") as fh:
      ids = [line.strip() for line in fh if line.strip()]
  except Exception as exc:
    print(f"ERROR: Could not read file '{filepath}': {exc}", file=sys.stderr)
    sys.exit(1)

  total = len(ids)
  print(f"Read {total} bug id(s) from '{filepath}'.")

  if total == 0:
    return

  for start in range(0, total, MAX_BATCH_SIZE):
    batch_ids = ids[start:start + MAX_BATCH_SIZE]
    keys = [client.key(kind, bid) for bid in batch_ids]

    if verbose:
      for k in keys:
        print(f"{'Would delete' if dry_run else 'Deleting'}: {k}")
    else:
      print(f"{'Would delete' if dry_run else 'Deleting'} batch {start // MAX_BATCH_SIZE + 1} "
            f"({len(keys)} keys)")

    if not dry_run:
      try:
        client.delete_multi(keys)
      except Exception as exc:
        print(f"Error deleting batch starting at index {start}: {exc}")
        raise

  if not dry_run:
    print("Delete operation completed.")
  else:
    print("Dry-run mode enabled; no entities were deleted.")


def main() -> None:
  args = parse_args()
  client = datastore.Client(project=args.project)

  if args.delete_from_file:
    if not args.file:
      print("ERROR: --delete-from-file requires --file <path>", file=sys.stderr)
      sys.exit(1)
    delete_from_file(client, args.file, args.verbose, args.dryrun)
    return

  # Default behavior: delete by source filter
  delete_by_source(client, args.source, args.verbose, args.dryrun)


if __name__ == "
