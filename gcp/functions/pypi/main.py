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
"""Cloud function for publishing PyPI vulnerabilities."""
import base64
import json

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from google.cloud import secretmanager
import requests

import osv

_ENDPOINT = 'https://pypi.org/_/vulnerabilities/osv/report'
_TIMEOUT = 30  # Timeout for HTTP(S) requests
_PROJECT_ID = '651737493649'
_SECRET_NAME = f'projects/{_PROJECT_ID}/secrets/pypi-key/versions/latest'


def _get_private_key():
  """Get the private key for signing the request."""
  client = secretmanager.SecretManagerServiceClient()
  response = client.access_secret_version(request={'name': _SECRET_NAME})
  return json.loads(response.payload.data)


def publish(event, context):
  """Publish PyPI vulnerability."""
  del context

  data = json.loads(base64.b64decode(event['data']))
  vulnerability = osv.parse_vulnerability_from_dict(data)

  key_data = _get_private_key()
  private_key = serialization.load_pem_private_key(
      data=key_data['key'].encode(), password=None)

  # TODO: Support multiple packages. Currently this only takes the first
  # package.
  package_name = None
  events = []
  versions = []
  for affected in vulnerability.affected:
    if affected.package.ecosystem != 'PyPI':
      continue

    if package_name:
      if affected.package.name != package_name:
        continue
    else:
      package_name = affected.package.name

    for affected_range in affected.ranges:
      if affected_range.type != osv.vulnerability_pb2.Range.ECOSYSTEM:
        continue

      for evt in affected_range.events:
        if evt.introduced:
          events.append({'introduced': evt.introduced})
        elif evt.fixed:
          events.append({'fixed': evt.fixed})

    versions.extend(affected.versions)

  if vulnerability.HasField('withdrawn'):
    events = []
    versions = []

  request = json.dumps([{
      'id': vulnerability.id,
      'project': package_name,
      'versions': versions,
      'link': f'https://osv.dev/vulnerability/{vulnerability.id}',
      'aliases': list(vulnerability.aliases),
      'details': vulnerability.details,
      'events': events,
  }]).encode()

  signature = private_key.sign(
      data=request, signature_algorithm=ECDSA(algorithm=SHA256()))
  headers = {
      'VULN-PUBLIC-KEY-IDENTIFIER': key_data['id'],
      'VULN-PUBLIC-KEY-SIGNATURE': base64.b64encode(signature).decode(),
  }

  print(f'Posting {vulnerability.id} to PyPI:', request.decode())
  response = requests.post(
      _ENDPOINT, data=request, headers=headers, timeout=_TIMEOUT)
  response.raise_for_status()
