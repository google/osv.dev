# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json
import subprocess

_GENERATED_FILENAME = 'osv_service_v1.swagger.json'


def main():
  subprocess.run([
      'protoc', '-I', '.', '-I', '../v1', '-I', '../googleapis', '-I', '../',
      '--openapiv2_out', '.', '--openapiv2_opt', 'logtostderr=true',
      '../v1/osv_service_v1.proto'
  ],
                 check=True)

  with open(_GENERATED_FILENAME) as f:
    spec = json.load(f)

  with open('faq.md') as f:
    faq = f.read()

  spec['host'] = 'api.osv.dev'
  spec['info']['title'] = 'OSV'
  spec['info']['version'] = '1.0'
  spec['tags'] = [{
      'name': 'api',
      'x-displayName': 'API',
      'description': 'API Endpoints'
  }, {
      'name':
          'vulnerability_schema',
      'x-displayName':
          'Vulnerability schema',
      'description':
          '<SchemaDefinition schemaRef="#/components/schemas/osvVulnerability" />'
  }, {
      'name':
          'faq',
      'x-displayName':
          'Frequently asked questions',
      'description': faq,
  }]

  spec['x-tagGroups'] = [{
      'name': 'API',
      'tags': ['api']
  }, {
      'name': 'Schema',
      'tags': ['vulnerability_schema']
  }, {
      'name': 'Documentation',
      'tags': ['faq']
  }]

  spec['paths']['/v1/query']['post']['tags'] = ['api']
  spec['paths']['/v1/vulns/{id}']['get']['tags'] = ['api']

  spec['paths']['/v1/query']['post']['x-code-samples'] = [{
      'lang': 'Bash',
      'source': (
          'curl -X POST -d \\\n'
          '  {"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"} \\\n'
          '  "https://api.osv.dev/v1/query?key=$API_KEY"')
  }]

  spec['paths']['/v1/vulns/{id}']['get']['x-code-samples'] = [{
      'lang': 'Bash',
      'source': 'curl "https://api.osv.dev/v1/vulns/2020-111?key=$API_KEY"'
  }]

  with open('sections.md') as f:
    spec['info']['description'] = f.read()

  with open(_GENERATED_FILENAME, 'w') as f:
    f.write(json.dumps(spec, indent=2))


if __name__ == '__main__':
  main()
