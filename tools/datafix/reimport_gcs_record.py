#!/usr/bin/env python3
"""Utility to trigger the reimport of individual GCS-sourced records.

Reimporting happens when:

* the creation time of the GCS object is newer than the last_update_date for
the data source in SourceRepository in Cloud Datastore
* either of:
  * the vulnerability does not exist in Bug in Cloud Datastore at all, or
  * the Modified field of the record differs from the existing Bug's
  import_last_modified in Cloud Datastore.

This defaults to running in dry-run mode against the staging instance. It
supports an arbitrary number of vulnerability IDs on the command line.
"""

from google.cloud import datastore
from google.cloud import storage
from google.cloud.exceptions import NotFound
from google.cloud.storage import retry
from google.cloud.datastore.query import PropertyFilter

import argparse
import os
import functools

MAX_QUERY_SIZE = 30


class UnexpectedSituation(Exception):
  pass


def objname_for_bug(client: datastore.Client, bug: datastore.entity.Entity,
                    forced_bucket_name: str) -> dict:
  """Returns the GCS object details for a given Bug.

  Args:
      client: an initialized Cloud Datastore client.
      bug: a Bug Cloud Datastore entity.
      forced_bucket_name: bucket name (with optional colon-separated path) to
      forcibly use.

  Returns:
    A dict with keys for the GCS uri, the bucket name and path within the
    bucket.
  """
  source_object_path = bug["source_id"].split(":")[1]

  if forced_bucket_name:
    (bucket, _, bucketpath) = forced_bucket_name.partition(":")
    # The assumption is that when passed a different bucket path, only the
    # current object's base filename is relevant.
    return {
        "uri":
            "gs://" + os.path.join(bucket, bucketpath,
                                   os.path.basename(source_object_path)),
        "bucket":
            bucket,
        "path":
            os.path.join(bucketpath, os.path.basename(source_object_path))
    }

  bucket = bucket_for_source(client, bug["source"])
  return {
      "uri": "gs://" + os.path.join(bucket, source_object_path),
      "bucket": bucket,
      "path": source_object_path
  }


def url_for_project(project: str) -> str:
  """Returns the base URL for referencing a vulnerability in the project.

  Args:
    project: a string representing the project ID.

  Returns:
    A string URL base for appending vulnerability IDs to.

  Raises:
    UnexpectedSituation if called with an unsupported project ID.
  """
  if project == "oss-vdb-test":
    return "https://test.osv.dev/"
  if project == "oss-vdb":
    return "https://osv.dev/"
  raise UnexpectedSituation(f"Unexpected project {project}")


@functools.cache
def bucket_for_source(client: datastore.Client, source: str) -> str:
  """Returns the GCS bucket name for a given source.

  Args:
    client: an initialized Cloud Datastore client.
    source: a string identifying the source to extract the GCS bucket name for.

  Returns:
    A string representing the GCS bucket name.

  Raises:
    UnexpectedSituation if called for a source that isn't using GCS, or more
    than one entry is returned.
  """
  query = client.query(kind="SourceRepository")
  query.add_filter(filter=PropertyFilter("name", "=", source))
  result = list(query.fetch())
  if len(result) != 1:
    raise UnexpectedSituation(
        f"More than one SourceRepository entry found for {source}")
  if result[0]['type'] != 1:
    raise UnexpectedSituation(f"The type for {source} isn't GCS")
  return result[0]['bucket']


def reset_object_modification(bucket_name: str, blob_name: str) -> None:
  """Resets a GCS object's creation time.

  Makes a no-op patch ("gcloud object storage objects update" equivalent)

  Args:
    bucket_name: the name of the GCS bucket.
    blob_name: the name of the object in the bucket.
  """
  gcs_client = storage.Client()
  bucket = gcs_client.bucket(bucket_name)
  blob = bucket.blob(blob_name)
  blob.patch(retry=retry.DEFAULT_RETRY)


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Trigger the reimport of individual GCS-sourced records")
  parser.add_argument(
      "bugs",
      action="append",
      nargs="+",
      help=f"The bug IDs to operate on ({MAX_QUERY_SIZE} at most)")
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
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  parser.add_argument(
      "--tmpdir",
      action="store",
      dest="tmpdir",
      default="/tmp",
      help="Local directory to copy to from GCS")
  parser.add_argument(
      "--bucket",
      action="store",
      dest="bucket",
      default=None,
      help=("Override the bucket name (and with a colon + path, the path) "
            "for the object in GCS (e.g. `cve-osv-conversion:osv-output`)"))
  args = parser.parse_args()

  if len(args.bugs[0]) > MAX_QUERY_SIZE:
    parser.error(f"Only {MAX_QUERY_SIZE} bugs can be supplied. "
                 f"Try running with xargs -n {MAX_QUERY_SIZE}")

  ds_client = datastore.Client(project=args.project)
  url_base = url_for_project(args.project)

  query = ds_client.query(kind="Bug")
  query.add_filter(filter=PropertyFilter("db_id", "IN", args.bugs[0]))
  print(f"Running query {query.filters[0]} "
        f"on {query.kind} (in {query.project})...")
  result = list(query.fetch())
  print(f"Retrieved {len(result)} bugs to validate for operating on")
  result_to_fix = [r for r in result if r['source_of_truth'] == 2]
  print(f"There are {len(result_to_fix)} bugs to operate on...")

  try:
    with ds_client.transaction() as xact:
      for bug in result_to_fix:
        try:
          bug_in_gcs = objname_for_bug(
              ds_client, bug, forced_bucket_name=args.bucket)
        except UnexpectedSituation as e:
          if args.verbose:
            print(f"Skipping {bug['db_id']}, got {e}\n")
          continue
        if args.verbose:
          print(f"Resetting modification time for {bug_in_gcs['uri']}")
        if not args.dryrun:
          try:
            reset_object_modification(bug_in_gcs["bucket"], bug_in_gcs["path"])
          except NotFound as e:
            if args.verbose:
              print(f"Skipping, got {e}\n")
            continue
        bug["import_last_modified"] = None
        if args.verbose:
          print(f"Resetting import_last_modified for {bug['db_id']}")
        print(f"Review at {url_base}{bug['db_id']} when reimport completes.")
        xact.put(bug)
      if args.dryrun:
        raise Exception("Dry run mode. Preventing transaction from commiting")  # pylint: disable=broad-exception-raised
  except Exception as e:
    # Don't have the first batch's transaction-aborting exception stop
    # subsequent batches from being attempted.
    if args.dryrun and e.args[0].startswith("Dry run mode"):
      pass
    else:
      raise


if __name__ == "__main__":
  main()
