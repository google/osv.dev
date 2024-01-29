"""Utility to sync sourcerepos from local yaml to datastore."""
from google.cloud import datastore
import yaml
import os
import sys

# path = os.path.dirname()
def main():
  kind = 'SourceRepositoryTest'

  file = 'source_repo_test_db.yaml'
  local_sourcerepos = []
  with open(os.path.join(sys.path[-1]+'/', file), 'r') as f:
    local_sourcerepos = yaml.load(f, Loader=yaml.FullLoader)
  print(f'Loaded {len(local_sourcerepos)} local source repositories')
  
  client = datastore.Client(project='oss-vdb-test')
  query = client.query(kind=kind)

  ds_repos = list(query.fetch())
  print(f'Retrieved {len(ds_repos)} source repositories from datastore')

  for repo in local_sourcerepos:
    repo_found = False
    for ds_repo in ds_repos:
      # if it exists, check if it needs to be updated
      if repo['name'] == ds_repo['name']:
        repo_found = True
        print(f'Found source repository {repo["name"]}')
        local_sourcerepos.pop(local_sourcerepos.index(repo))
        ds_repos.pop(ds_repos.index(ds_repo))
        change_flag = False
        for attr in repo:
          if attr in ds_repo:
            if repo[attr] != ds_repo[attr]:
              if change_flag is False:
                key = client.key(kind, ds_repo['name'])
                entity = client.get(key)
                change_flag = True
              print(f'Found diff in {attr} - {repo[attr]} != {ds_repo[attr]}')
              entity.update({attr: repo[attr]})
        if change_flag:
          client.put(entity)
        break
    # if it doesn't exist in the datastore, create it
    if not repo_found:
      print(f'New source repository {repo["name"]}')
      key = client.key(kind, repo['name'])
      entity = datastore.Entity(key=key)
      entity.update(repo)
      # print(entity)
      client.put(entity)

  # If the source repo is not in the local yaml, delete it
  for ds_repo in ds_repos:
    if ds_repo['name'] not in [repo['name'] for repo in local_sourcerepos]:
      print(f'Deleting source repository {ds_repo["name"]}')
      key = client.key(kind, ds_repo['name'])
      client.delete(key)

if __name__ == "__main__":
  main()
