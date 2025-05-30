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
from __future__ import annotations

import base64
import json
from typing import Any, Dict, List, Optional # Added Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec # Import ec module
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256
from google.cloud import secretmanager # type: ignore[attr-defined] # google.cloud.secretmanager.SecretManagerServiceClient
import requests

import osv # osv.models, osv.vulnerability_pb2

_ENDPOINT = 'https://pypi.org/_/vulnerabilities/osv/report'
_TIMEOUT = 30  # Timeout for HTTP(S) requests
_PROJECT_ID = '651737493649' # Should this be configurable?
_SECRET_NAME = f'projects/{_PROJECT_ID}/secrets/pypi-key/versions/latest'


def _get_private_key() -> Dict[str, str]: # Assuming 'id' and 'key' are strings
  """Get the private key for signing the request."""
  client = secretmanager.SecretManagerServiceClient()
  # Define the request structure for clarity, though not strictly needed for client.access_secret_version
  access_request = secretmanager.AccessSecretVersionRequest(name=_SECRET_NAME) # type: ignore[no-untyped-call]
  response = client.access_secret_version(request=access_request)
  # response.payload.data is bytes, needs decoding before json.loads
  payload_data: str = response.payload.data.decode('utf-8')
  key_info: Dict[str, str] = json.loads(payload_data)
  return key_info


def publish(event: Dict[str, Any], context: Any) -> None:
  """Publish PyPI vulnerability."""
  del context # Unused context parameter

  # Decode event data
  event_data_bytes: bytes = base64.b64decode(event['data'])
  event_data_dict: Dict[str, Any] = json.loads(event_data_bytes.decode('utf-8'))

  # Parse vulnerability from dict (osv.models.parse_vulnerability_from_dict)
  vulnerability: osv.vulnerability_pb2.Vulnerability = osv.parse_vulnerability_from_dict(event_data_dict)

  key_data: Dict[str, str] = _get_private_key()
  # Load private key using cryptography library
  # Assuming key_data['key'] is the PEM encoded private key string
  private_key: ec.EllipticCurvePrivateKey = serialization.load_pem_private_key(
      data=key_data['key'].encode('utf-8'), # Encode key string to bytes
      password=None # Assuming no password for the private key
  )

  # Extract relevant information for the PyPI report
  # TODO: Support multiple packages. Currently this only takes the first PyPI package.
  package_name: Optional[str] = None
  pypi_events: List[Dict[str, str]] = [] # Renamed events to avoid conflict
  pypi_versions: List[str] = [] # Renamed versions

  for affected_entry in vulnerability.affected: # Renamed affected
    if affected_entry.package.ecosystem != 'PyPI':
      continue

    if package_name: # If a PyPI package name is already found
      if affected_entry.package.name != package_name:
        # This logic implies we only report for the *first* PyPI package encountered.
        # If multiple PyPI packages are in `affected`, others are ignored.
        continue
    else: # First PyPI package found
      package_name = affected_entry.package.name

    # Collect ranges and versions for the matched PyPI package
    for affected_range_entry in affected_entry.ranges: # Renamed affected_range
      # PyPI report format uses 'ECOSYSTEM' ranges converted to 'events' list
      if affected_range_entry.type == osv.vulnerability_pb2.Range.Type.ECOSYSTEM: # Use enum value
        for evt_item in affected_range_entry.events: # Renamed evt
          if evt_item.introduced: # Check if field is set
            pypi_events.append({'introduced': evt_item.introduced})
          elif evt_item.fixed: # Check if field is set
            pypi_events.append({'fixed': evt_item.fixed})
          # PyPI format does not seem to use 'last_affected' or 'limit' directly in 'events'

    pypi_versions.extend(list(affected_entry.versions)) # Convert RepeatedScalarContainer to list

  # If the vulnerability is withdrawn, PyPI expects empty events and versions
  if vulnerability.HasField('withdrawn'):
    pypi_events = []
    pypi_versions = []

  if not package_name:
    print(f"No PyPI package found in vulnerability {vulnerability.id}. Skipping publish.")
    return

  # Construct the request payload for PyPI
  # PyPI expects a list containing a single report dictionary
  report_payload_list: List[Dict[str, Any]] = [{
      'id': vulnerability.id,
      'project': package_name,
      'versions': sorted(list(set(pypi_versions))), # Deduplicate and sort versions
      'link': f'https://osv.dev/vulnerability/{vulnerability.id}',
      'aliases': list(vulnerability.aliases), # Convert to list
      'details': vulnerability.details,
      'events': pypi_events, # Use the processed events
  }]
  request_body_bytes: bytes = json.dumps(report_payload_list).encode('utf-8') # Renamed request

  # Sign the request body
  signature_bytes: bytes = private_key.sign( # Renamed signature
      data=request_body_bytes,
      signature_algorithm=ECDSA(algorithm=SHA256()) # Use SHA256 for ECDSA
  )

  headers: Dict[str, str] = {
      'VULN-PUBLIC-KEY-IDENTIFIER': key_data['id'],
      'VULN-PUBLIC-KEY-SIGNATURE': base64.b64encode(signature_bytes).decode('utf-8'),
      'Content-Type': 'application/json' # Explicitly set Content-Type
  }

  print(f'Posting {vulnerability.id} to PyPI for package {package_name}: {request_body_bytes.decode("utf-8")}')
  response: requests.Response = requests.post(
      _ENDPOINT, data=request_body_bytes, headers=headers, timeout=_TIMEOUT)
  response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
  print(f"Successfully published {vulnerability.id} to PyPI. Response: {response.status_code}")
