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
"""Documentation builder."""

import json
import os
import shutil
import subprocess

_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GENERATED_FILENAME = 'v1/osv_service_v1.swagger.json'


def property_description_workaround(definition):
  """Work around an OpenAPI limitation with a field descriptions getting replaced
  by the object descriptions."""
  for value in definition['properties'].values():
    if '$ref' in value:
      value['allOf'] = [{'$ref': value['$ref']}]
      del value['$ref']


def main():
  api_dir = os.path.join(_ROOT_DIR, 'gcp', 'api')
  v1_api_dir = os.path.join(api_dir, 'v1')
  googleapis_dir = os.path.join(api_dir, 'googleapis')
  service_proto_path = os.path.join(v1_api_dir, 'osv_service_v1.proto')

  # Add OSV dependencies.
  osv_path = os.path.join(api_dir, 'osv')
  if os.path.exists(osv_path):
    shutil.rmtree(osv_path)

  shutil.copytree(os.path.join(_ROOT_DIR, 'lib', 'osv'), osv_path)

  subprocess.run([
      'protoc',
      '-I',
      api_dir,
      '-I',
      v1_api_dir,
      '-I',
      googleapis_dir,
      '--openapiv2_out',
      '.',
      '--openapiv2_opt',
      'logtostderr=true',
      service_proto_path,
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
      'description': 'The API has 2 methods:'
  }, {
      'name': 'vulnerability_schema',
      'x-displayName': 'Vulnerability schema',
      'description': '<SchemaDefinition schemaRef='
                     '"#/components/schemas/osvVulnerability" />'
  }, {
      'name': 'commit_schema',
      'x-displayName': 'Commit schema',
      'description': '<SchemaDefinition schemaRef='
                     '"#/components/schemas/osvCommit" />'
  }, {
      'name': 'faq',
      'x-displayName': 'Frequently asked questions',
      'description': faq,
  }]

  spec['x-tagGroups'] = [{
      'name': 'API',
      'tags': ['api']
  }, {
      'name': 'Schema',
      'tags': ['vulnerability_schema', 'commit_schema']
  }, {
      'name': 'Documentation',
      'tags': ['faq']
  }]

  spec['paths']['/v1/query']['post']['tags'] = ['api']
  spec['paths']['/v1/vulns/{id}']['get']['tags'] = ['api']

  spec['paths']['/v1/query']['post']['x-code-samples'] = [{
      'lang':
          'Curl example',
      'source':
          ('curl -X POST -d \\\n'
           '  \'{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}\' \\\n'
           '  "https://api.osv.dev/v1/query?key=$API_KEY"\n\n'
           'curl -X POST -d \\\n'
           '  \'{"package": {"name": "mruby"}, "version": "2.1.2rc"}\' \\\n'
           '  "https://api.osv.dev/v1/query?key=$API_KEY"')
  }]

  spec['paths']['/v1/vulns/{id}']['get']['x-code-samples'] = [{
      'lang': 'Curl example',
      'source': 'curl "https://api.osv.dev/v1/vulns/2020-111?key=$API_KEY"'
  }]

  property_description_workaround(spec['definitions']['v1Query'])
  property_description_workaround(spec['definitions']['osvVulnerability'])
  property_description_workaround(spec['definitions']['osvAffectedRange'])

  with open('sections.md') as f:
    spec['info']['description'] = f.read()

  with open(_GENERATED_FILENAME, 'w') as f:
    f.write(json.dumps(spec, indent=2))

  shutil.move(_GENERATED_FILENAME, os.path.basename(_GENERATED_FILENAME))


if __name__ == '__main__':
  main()
