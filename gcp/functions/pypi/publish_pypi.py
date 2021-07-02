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
_PROJECT_ID = 'oss-vdb'
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

  request = json.dumps({
      'id': vulnerability.id,
      'project': vulnerability.package.name,
      'versions': list(vulnerability.affects.versions),
      'link': f'https://osv.dev/vulnerability/{vulnerability.id}',
      'aliases': list(vulnerability.aliases),
  }).encode()

  signature = private_key.sign(
      data=request, signature_algorithm=ECDSA(algorithm=SHA256()))
  headers = {
      'VULN-PUBLIC-KEY-IDENTIFIER': key_data['id'],
      'VULN-PUBLIC-KEY-SIGNATURE': base64.b64encode(signature).decode(),
  }

  print(f'Posting {vulnerability.id} to PyPI.')
  requests.post(_ENDPOINT, data=request, headers=headers)
