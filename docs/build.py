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
  """Work around an OpenAPI limitation with a field descriptions getting
  replaced by the object descriptions."""
  # Workaround described in https://github.com/Redocly/redoc/issues/835.
  for value in definition['properties'].values():
    if '$ref' in value:
      value['allOf'] = [{'$ref': value['$ref']}]
      del value['$ref']


def replace_property_name(definition, key, replacement):
  """Replace property name."""
  definition['properties'][replacement] = definition['properties'][key]
  del definition['properties'][key]


def main():
  api_dir = os.path.join(_ROOT_DIR, 'gcp', 'api')
  v1_api_dir = os.path.join(api_dir, 'v1')
  googleapis_dir = os.path.join(api_dir, 'googleapis')
  service_proto_path = os.path.join(v1_api_dir, 'osv_service_v1.proto')

  # Add OSV dependencies.
  osv_path = os.path.join(api_dir, 'osv')
  if os.path.exists(osv_path):
    shutil.rmtree(osv_path)

  shutil.copytree(os.path.join(_ROOT_DIR, 'osv'), osv_path)

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

  spec['host'] = 'api.osv.dev'
  spec['info']['title'] = 'OSV'
  spec['info']['version'] = '1.0'
  spec['tags'] = [{
      'name': 'api',
      'x-displayName': 'API',
      'description': 'The API has 3 methods:'
  }, {
      'name': 'vulnerability_schema',
      'x-displayName': 'Vulnerability schema',
      'description': 'Please see the [OpenSSF Open Source Vulnerability spec]'
                     '(https://ossf.github.io/osv-schema/).',
  }]

  spec['x-tagGroups'] = [{
      'name': 'API',
      'tags': ['api']
  }, {
      'name': 'Schema',
      'tags': ['vulnerability_schema']
  }]

  spec['paths']['/v1/query']['post']['tags'] = ['api']
  spec['paths']['/v1/querybatch']['post']['tags'] = ['api']
  spec['paths']['/v1/vulns/{id}']['get']['tags'] = ['api']

  spec['paths']['/v1/query']['post']['x-code-samples'] = [{
      'lang':
          'Curl example',
      'source':
          ('curl -X POST -d \\\n'
           '  \'{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}\' \\\n'
           '  "https://api.osv.dev/v1/query"\n\n'
           'curl -X POST -d \\\n'
           '  \'{"package": {"name": "mruby"}, "version": "2.1.2rc"}\' \\\n'
           '  "https://api.osv.dev/v1/query"')
  }]

  spec['paths']['/v1/querybatch']['post']['x-code-samples'] = [{
      'lang':
          'Curl example',
      'source':
          ("""cat <<EOF | curl -X POST -d @- "https://api.osv.dev/v1/querybatch"
{
  "queries": [
    {
      "package": {
        "purl": "pkg:pypi/antlr4-python3-runtime@4.7.2"
      }
    },
    {
      "commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"
    },
    {
      "package": {
        "ecosystem": "PyPI",
        "name": "jinja2"
      },
      "version": "2.4.1"
    }
  ]
}
EOF""")
  }]

  spec['paths']['/v1/vulns/{id}']['get']['x-code-samples'] = [{
      'lang': 'Curl example',
      'source': 'curl "https://api.osv.dev/v1/vulns/OSV-2020-111"'
  }]

  property_description_workaround(spec['definitions']['v1Query'])
  property_description_workaround(spec['definitions']['osvVulnerability'])

  replace_property_name(spec['definitions']['osvVulnerability'],
                        'databaseSpecific', 'database_specific')

  with open('sections.md') as f:
    spec['info']['description'] = f.read()

  with open(_GENERATED_FILENAME, 'w') as f:
    f.write(json.dumps(spec, indent=2))

  shutil.move(_GENERATED_FILENAME, os.path.basename(_GENERATED_FILENAME))


if __name__ == '__main__':
  main()
