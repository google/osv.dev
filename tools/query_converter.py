import argparse
import json
from urllib import request
import subprocess

IMAGE_TO_RUN = 'node'


def chunks(lst, n):
  for i in range(0, len(lst), n):
    yield lst[i:i + n]


QUERY_BATCH_ENDPOINT = 'https://api.osv.dev/v1/querybatch'


def load_vulns(image_to_run):

  stuff = subprocess.check_output([
      'docker', 'run', '--rm', image_to_run, '/usr/bin/dpkg-query', '-f',
      '${Package}###${Version}\\n', '-W'
  ]).decode('utf-8')

  results = []
  print(stuff)
  # with open('packages.txt', 'r') as handle:
  lines = stuff.splitlines()
  for line in lines:
    if len(line.strip('\n')) == 0:
      continue
    package, version = line.strip('\n').split("###")
    results.append({
        'version': version,
        'package': {
            'name': package,
            'ecosystem': 'Debian',
        }
    })

  for elem in chunks(results, 900):
    query = {'queries': elem}
    query_json = json.dumps(query)
    print(query_json)
    with request.urlopen(QUERY_BATCH_ENDPOINT, query_json.encode()) as res:
      data = json.loads(res.read().decode('utf-8'))
      results = zip(data['results'], elem)

      results = [x for x in results if x[0] != {}]
      print(json.dumps(results, indent=2))


if __name__ == '__main__':
  parser = argparse.ArgumentParser()
  parser.add_argument('docker_image_name')
  args = parser.parse_args()
  print(args)
  load_vulns(args.docker_image_name)
