"""Utility to sync sourcerepos from local yaml to datastore."""
from google.cloud import datastore
import yaml
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
  parser.add_argument(
      "--file",
      action="store",
      dest="file",
      default="../../source_test.yaml",
      help="Source of 'truth' yaml file - if at root use ../../<file.yaml>")
  parser.add_argument(
      "--validate",
      action=argparse.BooleanOptionalAction,
      dest="validate",
      default=False,
      help="Validate the yaml file only")

  args = parser.parse_args()

  file = args.file
  local_sourcerepos = []
  with open(file, 'r') as f:
    local_sourcerepos = yaml.safe_load(f)
  if args.verbose:
    print(f'Loaded {len(local_sourcerepos)} local source repositories')

  # Validate the yaml file
  # Check sourcerepo for duplicates:
  def validate_repository(repository, local=True):
    """Check the attributes of the source repo."""
    sourcerepo_names = []
    for repo in repository:
      if repo['name'] == '' or repo['name'] is None or repo['name'] == 'null':
        raise ValueError(f'Empty sourcerepo name in {file}')
      if repo['name'] in sourcerepo_names:
        raise ImportError(f'Duplicate sourcerepo name {repo["name"]} in {file}')
      sourcerepo_names.append(repo['name'])
      # Make sure the link ends with a /
      if 'link' in repo and repo['link'][-1] != '/':
        raise ValueError(f'Link in {repo["name"]} missing ending /')
      # Check for a dynamic field being mistakenly pushed
      if local:
        dynamic_fields = {
            'last_update_date', 'ignore_last_import_time', 'last_synced_hash'
        }
        for field in dynamic_fields:
          if field in repo:
            raise ValueError(f'Dynamic field {field} found in {repo["name"]}')
    if args.verbose:
      print(f'Validated {len(repository)} source repositories')
  
  def create_sourcerepo():
    """Create a new source repo."""
    if args.file.startswith('../../'):
      default_file = 'source_repo_default.yaml'
    else:
      default_file = 'tools/sourcerepo-sync/source_repo_default.yaml'
    with open(default_file, 'r') as f:
      default_entity = yaml.safe_load(f)
    if args.verbose:
      print(f'New source repository {repo["name"]}')
    key = client.key(args.kind, repo['name'])
    entity = datastore.Entity(key=key)
    # Set defaults if not given in yaml
    entity.update({'name': repo['name']})
    for attr in default_entity:
      if attr in repo:
        if attr == 'link' and repo[attr][-1] != '/':
          raise ValueError(f'Link in {repo["name"]} missing ending /')
        entity.update({attr: repo[attr]})
      else:
        entity.update({attr: default_entity[attr]})
    if not args.dryrun:
      client.put(entity)

  def update_sourcerepo():
    """Check the attributes of the source repo and update if needed."""
    change_flag = False
    for attr in repo:
      #Check whether the attribute has changed
      if attr not in ds_repo or repo[attr] == ds_repo[attr]:
        continue
      if change_flag is False:
        key = client.key(args.kind, ds_repo['name'])
        entity = client.get(key)
        change_flag = True
      if args.verbose:
        name = repo['name']
        print(f'Found diff in {name}: {attr} - {repo[attr]} != {ds_repo[attr]}')
      entity.update({attr: repo[attr]})

    if change_flag and not args.dryrun:
      client.put(entity)

  validate_repository(local_sourcerepos)

  if not args.validate:
    client = datastore.Client(project=args.project)
    query = client.query(kind=args.kind)
    ds_repos = list(query.fetch())
    if args.verbose:
      print(f'Retrieved {len(ds_repos)} source repositories from datastore')
    validate_repository(ds_repos, False)
    for repo in local_sourcerepos:
      repo_found = False
      for ds_repo in ds_repos:
        # if it exists, check if it needs to be updated
        if repo['name'] == ds_repo['name']:
          repo_found = True
          if args.verbose:
            print(f'Found source repository {repo["name"]}')
          ds_repos.pop(ds_repos.index(ds_repo))
          update_sourcerepo()

      if repo_found:
        continue
      create_sourcerepo()

    local_sourcerepos_names = {repo['name'] for repo in local_sourcerepos}
    # If the source repo is not in the local yaml, delete it
    for ds_repo in ds_repos:
      if ds_repo['name'] not in local_sourcerepos_names:
        if args.verbose:
          print(f'Deleting source repository {ds_repo["name"]}')
        key = client.key(args.kind, ds_repo['name'])
        if not args.dryrun:
          client.delete(key)


if __name__ == "__main__":
  main()
