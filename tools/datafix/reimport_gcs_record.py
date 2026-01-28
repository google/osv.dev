#!/usr/bin/env python3
"""Utility to trigger the reimport of individual GCS-sourced records.

Reimporting happens when:

* the creation time of the GCS object is newer than the last_update_date for
the data source in SourceRepository in Cloud Datastore
* either of:
  * the vulnerability does not exist in Vulnerability in Datastore at all, or
  * the Modified field of the record differs from the existing Vulnerability's
  modified_raw in Cloud Datastore.

This defaults to running in dry-run mode against the staging instance. It
supports an arbitrary number of vulnerability IDs on the command line.
"""

from google.cloud import datastore
from google.cloud import storage
from google.cloud.exceptions import NotFound
from google.cloud.storage import retry
from google.cloud.datastore.query import PropertyFilter

import argparse
from datetime import datetime, timezone
import os
import functools

MAX_QUERY_SIZE = 30


class UnexpectedSituation(Exception):
  pass


def objname_for_vuln(client: datastore.Client, vuln: datastore.entity.Entity,
                     forced_bucket_name: str) -> dict:
  """Returns the GCS object details for a given Vulnerability.

  Args:
      client: an initialized Cloud Datastore client.
      vuln: a Vulnerability Cloud Datastore entity.
      forced_bucket_name: bucket name (with optional colon-separated path) to
      forcibly use.

  Returns:
    A dict with keys for the GCS uri, the bucket name and path within the
    bucket.
  """
  source, _, source_object_path = vuln["source_id"].partition(":")

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

  bucket = bucket_for_source(client, source)
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
      "vulns",
      action="append",
      nargs="+",
      help=f"The vuln IDs to operate on ({MAX_QUERY_SIZE} at most)")
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

  if len(args.vulns[0]) > MAX_QUERY_SIZE:
    parser.error(f"Only {MAX_QUERY_SIZE} vulns can be supplied. "
                 f"Try running with xargs -n {MAX_QUERY_SIZE}")

  ds_client = datastore.Client(project=args.project)
  url_base = url_for_project(args.project)

  print("Running fetch")
  result = ds_client.get_multi(
      [ds_client.key('Vulnerability', vuln_id) for vuln_id in args.vulns[0]])
  print(f"Retrieved {len(result)} vulns to operate on...")

  try:
    with ds_client.transaction() as xact:
      for vuln in result:
        try:
          vuln_in_gcs = objname_for_vuln(
              ds_client, vuln, forced_bucket_name=args.bucket)
        except UnexpectedSituation as e:
          if args.verbose:
            print(f"Skipping {vuln.key.name}, got {e}\n")
          continue
        if args.verbose:
          print(f"Resetting modification time for {vuln_in_gcs['uri']}")
        if not args.dryrun:
          try:
            reset_object_modification(vuln_in_gcs["bucket"],
                                      vuln_in_gcs["path"])
          except NotFound as e:
            if args.verbose:
              print(f"Skipping, got {e}\n")
            continue
        vuln["modified_raw"] = datetime.fromtimestamp(0, timezone.utc)
        if args.verbose:
          print(f"Resetting modified_raw for {vuln.key.name}")
        print(f"Review at {url_base}{vuln.key.name} when reimport completes.")
        xact.put(vuln)
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
