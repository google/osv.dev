
from google.cloud import datastore

import os
import sys

file = 'sourcerepositorytest.yaml'
local_sourcerepos = []

client = datastore.Client(project='oss-vdb-test')
query = client.query(kind='SourceRepository')
results = list(query.fetch())
print(f'Retrieved {len(results)} sourcerepos')
sources = ''
for result in results:
  name = result['name']
  sourcerepo = f'- name: {name}\n'
  for attr in result:
    if attr == 'name':
      continue
    # Skip dynamic attribute
    if attr == 'last_update_date' or attr == 'ignore_last_import_time':
      continue

    elif result[attr] != '' and result[attr] is not None and result[attr] != []:
      sourcerepo += f'  {attr}: {result[attr]}\n'

  print(sourcerepo)
  sources += sourcerepo + '\n'

with open(os.path.join(sys.path[-1]+'/', file), 'w') as f:
  f.write(sources)
