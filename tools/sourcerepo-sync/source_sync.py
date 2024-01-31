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
    local_sourcerepos = yaml.safe_load(f)
  if args.verbose:
    print(f'Loaded {len(local_sourcerepos)} local source repositories')

  # Check sourcerepo for duplicates:
  sourcerepo_names = []
  for repo in local_sourcerepos:
    if repo['name'] == '' or repo['name'] is None or repo['name'] == 'null':
      raise ValueError(f'Empty sourcerepo name in {file}')
    if repo['name'] in sourcerepo_names:
      raise ImportError(f'Duplicate sourcerepo name {repo["name"]} in {file}')
    sourcerepo_names.append(repo['name'])

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
        ds_repos.pop(ds_repos.index(ds_repo))
        update_sourcerepo(repo, ds_repo, args, client, args.kind)

    if repo_found:
      continue
    create_sourcerepo(repo, args, client, args.kind)

  local_sourcerepos_names = {repo['name'] for repo in local_sourcerepos}
  # If the source repo is not in the local yaml, delete it
  for ds_repo in ds_repos:
    if ds_repo['name'] not in local_sourcerepos_names:
      if args.verbose:
        print(f'Deleting source repository {ds_repo["name"]}')
      key = client.key(args.kind, ds_repo['name'])
      if not args.dryrun:
        client.delete(key)


def create_sourcerepo(repo, args, client, kind):
  """Create a new source repo."""
  with open('source_repo_default.yaml', 'r') as f:
    default_entity = yaml.safe_load(f)
  if args.verbose:
    print(f'New source repository {repo["name"]}')
  key = client.key(kind, repo['name'])
  entity = datastore.Entity(key=key)
  # Set defaults if not given in yaml
  for attr in default_entity:
    if attr in repo:
      entity.update({attr: repo[attr]})
    else:
      entity.update({attr: default_entity[attr]})
  if not args.dryrun:
    client.put(entity)


def update_sourcerepo(repo, ds_repo, args, client, kind):
  """Check the attributes of the source repo and update if needed."""
  change_flag = False
  for attr in repo:
    #Check whether the attribute has changed
    if attr not in ds_repo or repo[attr] == ds_repo[attr]:
      continue
    if change_flag is False:
      key = client.key(kind, ds_repo['name'])
      entity = client.get(key)
      change_flag = True
    if args.verbose:
      name = repo['name']
      print(f'Found diff in {name}: {attr} - {repo[attr]} != {ds_repo[attr]}')
    entity.update({attr: repo[attr]})

  if change_flag and not args.dryrun:
    client.put(entity)


if __name__ == "__main__":
  main()
