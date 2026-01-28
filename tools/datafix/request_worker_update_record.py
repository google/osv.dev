#!/usr/bin env python
"""Publish PubSub messages asking the worker to (re)process record.

Tip: Invoke via xargs to process multiple records from a file,
e.g. cat records | xargs ...
"""

import argparse
import time
from google.cloud import pubsub_v1
from google.cloud import ndb
import osv
import requests
from urllib.parse import urlparse

DEFAULT_TIMEOUT = 60
PUBSUB_TOPIC_ID = "tasks"


def publish_update_message(project_id,
                           topic_id,
                           source,
                           path,
                           original_sha256,
                           deleted=False):
  """Publish a message to a Pub/Sub topic with the provided data as attributes.

  Args:
      project_id: The ID of the GCP project.
      topic_id: The ID of the Pub/Sub topic.
      source: The record source ID.
      path: The record path.
      original_sha256: The original SHA256 checksum of the record.
      deleted: Whether the record has been deleted.
  """

  publisher = pubsub_v1.PublisherClient()
  topic_path = publisher.topic_path(project_id, topic_id)

  # Create a PubsubMessage object with empty data and attributes
  message = pubsub_v1.types.PubsubMessage(
      data=b"",  # Empty data field
      attributes={
          "type": "update",
          "source": source,
          "path": path,
          "original_sha256": original_sha256,
          "deleted": "true" if deleted else "false",
          "req_timestamp": str(int(time.time())),
      },
  )

  print(f'Publishing: {message.attributes}')
  future = publisher.publish(topic_path, message.data, **message.attributes)
  print(f"Published message ID: {future.result()}")


def github_raw_url(repo_url, path):
  """Get a downloadable raw URL for a path in a github repo."""
  parsed = urlparse(repo_url.removesuffix('.git'))
  if parsed.hostname != 'github.com':
    raise ValueError(f'{repo_url} is not a GitHub URL')

  repo = '/'.join(parsed.path.split('/')[1:3])
  return f'https://raw.githubusercontent.com/{repo}/refs/heads/main/' + path


def request_url_update(record_url, project_id, source, path, timeout,
                       allow_delete):
  """Request a update based on a URL record."""
  print(f'Trying: {record_url}')
  response = requests.get(record_url, timeout=timeout)
  original_sha256 = ''
  deleted = False
  try:
    response.raise_for_status()
    original_sha256 = osv.sha256_bytes(response.text.encode())
  except requests.HTTPError as e:
    if not allow_delete or e.response.status_code != 404:
      print(e)
      return
    print(f'Vulnerability was deleted: {record_url}')
    deleted = True

  publish_update_message(project_id, PUBSUB_TOPIC_ID, source, path,
                         original_sha256, deleted)


def main():
  parser = argparse.ArgumentParser(
      description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  parser.add_argument(
      "--project_id", required=True, help="The Google Cloud project ID")
  parser.add_argument("--source", required=True, help="The record source ID")
  parser.add_argument(
      "--timeout",
      type=int,
      default=DEFAULT_TIMEOUT,
      help="Default timeout to use for operations")
  parser.add_argument(
      "--allow-delete",
      action="store_true",
      default=False,
      help="Delete vulns if not found in source (GIT only)")
  parser.add_argument(
      "vulns",
      action="append",
      nargs="*",
      help="The vuln IDs to operate on. If not specified, all vulns from the "
      "source will be processed.")

  args = parser.parse_args()

  datastore_client = ndb.Client(args.project_id)

  with datastore_client.context():
    source_repo = osv.SourceRepository.get_by_id(args.source)
    if not source_repo:
      raise ValueError(f"Source repository '{args.source}' not found.")

    vulns_to_process = []
    if args.vulns and args.vulns[0]:
      vulns_to_process = args.vulns[0]
    else:
      print('No vuln IDs provided. '
            'Querying all vulns for source {args.source}...')
      query = osv.Vulnerability.query(
          osv.Vulnerability.source_id > args.source + ':',
          osv.Vulnerability.source_id < (args.source + ';'))
      vulns_to_process = [b.id() for b in query.iter(keys_only=True)]
      print(f'Found {len(vulns_to_process)} bugs to update.')
      confirm = input('Are you sure you want to proceed? (y/N) ')
      if confirm.lower() not in ('y', 'yes'):
        print('Aborting.')
        return

    if source_repo.type == osv.SourceRepositoryType.REST_ENDPOINT:
      for vuln in vulns_to_process:
        record_url = f'{source_repo.link}{vuln}{source_repo.extension}'
        path = f'{vuln}{source_repo.extension}'
        request_url_update(record_url, args.project_id, args.source, path,
                           args.timeout, False)

    if source_repo.type == osv.SourceRepositoryType.GIT:
      for vuln in vulns_to_process:
        entity = osv.Vulnerability.get_by_id(vuln)
        if not entity:
          print(f'Warning: {vuln} does not exist in Datastore, skipping.')
          continue

        path = entity.source_id.split(':')[1]

        record_url = github_raw_url(source_repo.repo_url, path)
        request_url_update(record_url, args.project_id, args.source, path,
                           args.timeout, args.allow_delete)

    if source_repo.type == osv.SourceRepositoryType.BUCKET:
      raise NotImplementedError("Use reimport_gcs_record.py for now")


if __name__ == "__main__":
  main()
