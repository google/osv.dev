"""Utility to sync sourcerepos from local yaml to datastore."""
from google.cloud import datastore
import yaml
import os
import sys
import argparse


def main() -> None:
  parser = argparse.ArgumentParser(
      description="Sync source repositories from local yaml to datastore.")
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
      "--kind",
      action="store",
      dest="kind",
      default="SourceRepositoryTest",  # Change to SourceRepository
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
  local_sourcerepos = []
  with open(os.path.join(sys.path[-1] + '/', file), 'r') as f:
    local_sourcerepos = yaml.load(f, Loader=yaml.FullLoader)
  if args.verbose:
    print(f'Loaded {len(local_sourcerepos)} local source repositories')

  client = datastore.Client(project=args.project)
  query = client.query(kind=args.kind)

  ds_repos = list(query.fetch())
  if args.verbose:
    print(f'Retrieved {len(ds_repos)} source repositories from datastore')

  for repo in local_sourcerepos:
    repo_found = False
    for ds_repo in ds_repos:
      # if it exists, check if it needs to be updated
      if repo['name'] == ds_repo['name']:
        repo_found = True
        if args.verbose:
          print(f'Found source repository {repo["name"]}')
        local_sourcerepos.pop(local_sourcerepos.index(repo))
        ds_repos.pop(ds_repos.index(ds_repo))
        change_flag = False
        change_flag, entity = update_attr(repo, ds_repo, change_flag, args,
                                          client, args.kind)
        if change_flag and not args.dryrun:
          client.put(entity)
        break
    # if it doesn't exist in the datastore, create it
    if not repo_found:
      if args.verbose:
        print(f'New source repository {repo["name"]}')
      key = client.key(args.kind, repo['name'])
      entity = datastore.Entity(key=key)
      entity.update(repo)
      if not args.dryrun:
        client.put(entity)

  # If the source repo is not in the local yaml, delete it
  for ds_repo in ds_repos:
    if ds_repo['name'] not in [repo['name'] for repo in local_sourcerepos]:
      if args.verbose:
        print(f'Deleting source repository {ds_repo["name"]}')
      key = client.key(args.kind, ds_repo['name'])
      if not args.dryrun:
        client.delete(key)


def update_attr(repo, ds_repo, change_flag, args, client, kind):
  """Check the attributes of the source repo and update if needed."""
  for attr in repo:
    if attr in ds_repo:
      if repo[attr] != ds_repo[attr]:
        if change_flag is False:
          key = client.key(kind, ds_repo['name'])
          entity = client.get(key)
          change_flag = True
        if args.verbose:
          print(f'Found diff in {attr} - {repo[attr]} != {ds_repo[attr]}')
        entity.update({attr: repo[attr]})
  return change_flag, entity


if __name__ == "__main__":
  main()
