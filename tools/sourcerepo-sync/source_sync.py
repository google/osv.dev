"""Utility to sync sourcerepos from local yaml to datastore."""
from google.cloud import datastore
import yaml
import os
import sys

# path = os.path.dirname()
def main():
  file = 'sourcerepository.yaml'
  local_sourcerepos = []
  with open(os.path.join(sys.path[-1]+'/', file), 'r') as f:
    local_sourcerepos = yaml.load(f, Loader=yaml.FullLoader)
  print(f'Loaded {len(local_sourcerepos)} sourcerepos')
  for repo in local_sourcerepos:
    print(repo['name'])

  client = datastore.Client(project='oss-vdb-test')
  query = client.query(kind='SourceRepositoryTest')

  ds_repos = list(query.fetch())
  print(f'Retrieved {len(ds_repos)} sourcerepos')

  for repo in local_sourcerepos:
    for ds_repo in ds_repos:
      if repo['name'] == ds_repo['name']:
        print(f'Found sourcerepo {repo["name"]}')
        local_sourcerepos.pop(local_sourcerepos.index(repo))
        ds_repos.pop(ds_repos.index(ds_repo))
        change_flag = False
        for attr in repo:
          if attr in ds_repo:
            if repo[attr] != ds_repo[attr]:
              if change_flag is False:
                key = client.key('SourceRepositoryTest', ds_repo['name'])
                entity = client.get(key)
                change_flag = True
              print(f'Found diff in {attr} - {repo[attr]} != {ds_repo[attr]}')
              entity.update({attr: repo[attr]})
        if change_flag:
          client.put(entity)
          #print(entity)

        break


if __name__ == "__main__":
  main()
