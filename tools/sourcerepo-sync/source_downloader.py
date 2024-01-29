
from google.cloud import datastore
import yaml
import os
import sys

file = 'sourcerepositorytest.yaml'
local_sourcerepos = []

client = datastore.Client(project='oss-vdb-test')
query = client.query(kind='SourceRepository')
results = list(query.fetch())
# print(f'Retrieved {len(results)} sourcerepos')

for result in results:
  name = result['name']
  sourcerepo = f'- name: \'{name}\'\n'
  for attr in result:
    if attr == 'name':
      continue
      # print(f'{attr}: \'{result[attr]}\'')
    elif result[attr] != '' and result[attr] is not None:
      sourcerepo += f' {attr}: \'{result[attr]}\'\n'
      # print(f'{attr}: \'{result[attr]}\'')
  print(sourcerepo)
# yaml.dump(sourcerepo, open(
#   os.path.join(sys.path[-1]+'/', file), 'w'), default_flow_style=True)


# Write a new yaml file with the sourcerepos from the datastore
# with open(os.path.join(sys.path[-1]+'/', file), 'w') as f:
#   local_sourcerepos = yaml.load(f, Loader=yaml.FullLoader)
# print(f'Loaded {len(local_sourcerepos)} sourcerepos')