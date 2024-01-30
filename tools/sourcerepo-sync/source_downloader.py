""" Download source repository data from datastore and write to yaml file"""
from google.cloud import datastore

import os
import sys
import argparse


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Sync source repositories from local yaml to datastore.")
  parser.add_argument(
      "--verbose",
      action=argparse.BooleanOptionalAction,
      dest="verbose",
      default=True,
      help="Display records being operated on")
  parser.add_argument(
      "--kind",
      action="store",
      dest="kind",
      default="SourceRepository",
      help="The datastore kind to operate on")
  parser.add_argument(
      "--project",
      action="store",
      dest="project",
      default="oss-vdb-test",
      help="GCP project to operate on")
  args = parser.parse_args()

  if args.project == 'oss-vdb-test':
    file = 'source_test.yaml'
  elif args.project == 'oss-vdb':
    file = 'source.yaml'
  else:
    print('Invalid project')
    return

  client = datastore.Client(project=args.project)
  query = client.query(kind=args.kind)
  results = list(query.fetch())
  if args.verbose:
    print(f'Retrieved {len(results)} sourcerepos')
  sources = ''
  for result in results:
    name = result['name']
    sourcerepo = f'- name: {name}\n'
    for attr in result:
      if attr == 'name':
        continue
      # Skip dynamic attribute
      if attr in ('last_update_date', 'ignore_last_import_time', 'last_synced_hash'):
        continue
      if result[attr] != '' and result[attr] is not None and result[attr] != []:
        sourcerepo += f'  {attr}: {result[attr]}\n'

    if args.verbose:
      print(sourcerepo)
    sources += sourcerepo + '\n'

  with open(os.path.join(sys.path[-1] + '/', file), 'w') as f:
    f.write(sources)


if __name__ == "__main__":
  main()
