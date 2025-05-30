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
"""publish_pypi tests."""
# pylint: disable=line-too-long

from __future__ import annotations

import base64
import os
import unittest
from unittest import mock
from typing import Any, Dict # Added Any, Dict

from cryptography.hazmat.primitives import hashes, serialization # Import hashes
from cryptography.hazmat.primitives.asymmetric import ec # Import ec
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
# SHA256 is available in hashes module, ECDSA in ec.
# from cryptography.hazmat.primitives.hashes import SHA256 # Already imported via hashes

import main # from gcp.functions.pypi import main

_TEST_DATA_DIR = 'testdata'
# _TIMEOUT is already correctly inferred as int from main._TIMEOUT
_TIMEOUT: int = main._TIMEOUT  # pylint: disable=protected-access


def _load_test_data(name: str) -> bytes:
  """Load test data."""
  # Construct path relative to this test file's directory might be more robust
  # For now, assume 'testdata' is relative to CWD where tests are run.
  # If tests are run from repository root, path should be 'gcp/functions/pypi/testdata'
  # Correcting path to be relative to this file's location:
  base_dir = os.path.dirname(__file__)
  file_path = os.path.join(base_dir, _TEST_DATA_DIR, name)
  with open(file_path, 'rb') as f:
    return f.read()


_TEST_VULN: bytes = _load_test_data("test_vuln.json")
_TEST_VULN_WITHDRAWN: bytes = _load_test_data("test_vuln_withdrawn.json")
_FAKE_SECRET: bytes = _load_test_data("fake_secret.json")
_FAKE_PUB_KEY: bytes = _load_test_data("fake_pub_key.pem")


class PublishPyPiTest(unittest.TestCase):
  """Tests for publish_pypi."""

  mock_post: mock.Mock # For requests.post mock

  def setUp(self) -> None:
    # Patch SecretManagerServiceClient
    patcher_secret_client = mock.patch( # Renamed patcher
        'google.cloud.secretmanager.SecretManagerServiceClient')
    mock_secret_manager_constructor = patcher_secret_client.start() # Renamed mock_secret_client
    self.addCleanup(patcher_secret_client.stop)

    # Configure the mock client instance's access_secret_version method
    mock_secret_payload = mock.MagicMock() # Renamed mock_secret
    mock_secret_payload.payload.data = _FAKE_SECRET
    # mock_secret_manager_constructor() gives the mock SecretManagerServiceClient instance
    mock_secret_manager_constructor().access_secret_version.return_value = mock_secret_payload

    # Patch requests.post
    patcher_requests_post = mock.patch('requests.post') # Renamed patcher
    self.mock_post = patcher_requests_post.start()
    self.addCleanup(patcher_requests_post.stop)

  def _verify_signature(self, request_data: bytes, signature_b64: str) -> None: # Renamed request, signature
    """Verify signature."""
    # Load public key (ensure _FAKE_PUB_KEY is bytes)
    public_key: ec.EllipticCurvePublicKey = serialization.load_pem_public_key(data=_FAKE_PUB_KEY)

    # Decode the base64 signature to bytes
    signature_bytes: bytes = base64.b64decode(signature_b64)

    # Verify signature
    # Type for algorithm in ECDSA is hashes.HashAlgorithm. SHA256() is an instance of it.
    public_key.verify(
        signature=signature_bytes,
        data=request_data,
        signature_algorithm=ECDSA(algorithm=hashes.SHA256()), # Use hashes.SHA256()
    )

  def test_publish(self) -> None:
    """Test publishing."""
    event_payload: Dict[str, bytes] = { # Renamed event
        'data': base64.b64encode(_TEST_VULN), # data is b64 encoded bytes
    }

    # Context is Any, can pass None for this test if not used by the function
    main.publish(event_payload, None) # type: ignore[arg-type] # event dict value type mismatch Dict[str,Any] vs Dict[str,bytes]
                                      # main.publish expects event: Dict[str, Any]. b64encode returns bytes.
                                      # This is fine as Any can be bytes.

    # Expected data for PyPI API (as bytes)
    expected_data_bytes = (
        b'[{"id": "PYSEC-2021-63", "project": "cryptography", '
        b'"versions": ["3.1", "3.1.1", "3.2", "3.2.1", "3.3", "3.3.1"], '
        b'"link": "https://osv.dev/vulnerability/PYSEC-2021-63", '
        b'"aliases": ["CVE-2020-36242"], '
        b'"details": "In the cryptography package before 3.3.2 for Python, certain sequences of update calls to symmetrically encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the Fernet class.", '
        b'"events": [{"introduced": "3.1"}, {"fixed": "3.1.2"}, {"introduced": "3.2"}, {"fixed": "3.3.2"}]'
        b'}]'
    )
    # Expected headers for PyPI API
    expected_headers: Dict[str, Any] = { # Value for signature is mock.ANY
        'VULN-PUBLIC-KEY-IDENTIFIER': '7ef88907d5bba4c0120f82bfd78386a9'
                                      'd9328fb5d2d112c473ce52add3e4cd5b',
        'VULN-PUBLIC-KEY-SIGNATURE': mock.ANY,
        'Content-Type': 'application/json' # Added from main.py logic
    }

    self.mock_post.assert_called_once_with(
        'https://pypi.org/_/vulnerabilities/osv/report',
        data=expected_data_bytes,
        headers=expected_headers,
        timeout=_TIMEOUT)

    # Extract actual request data and signature from mock call to verify signature
    actual_request_data: bytes = self.mock_post.call_args.kwargs['data']
    actual_signature_b64: str = self.mock_post.call_args.kwargs['headers']['VULN-PUBLIC-KEY-SIGNATURE']
    self._verify_signature(actual_request_data, actual_signature_b64)

  def test_publish_withdrawn(self) -> None:
    """Test publishing withdrawn vulnerability."""
    event_payload_withdrawn: Dict[str, bytes] = { # Renamed event
        'data': base64.b64encode(_TEST_VULN_WITHDRAWN),
    }

    main.publish(event_payload_withdrawn, None) # type: ignore[arg-type] # Same as above for event type

    expected_data_withdrawn_bytes = (
        b'[{"id": "PYSEC-2021-63", "project": "cryptography", '
        b'"versions": [], ' # Key difference for withdrawn: empty versions
        b'"link": "https://osv.dev/vulnerability/PYSEC-2021-63", '
        b'"aliases": ["CVE-2020-36242"], '
        b'"details": "In the cryptography package before 3.3.2 for Python, certain sequences of update calls to symmetrically encrypt multi-GB values could result in an integer overflow and buffer overflow, as demonstrated by the Fernet class.", '
        b'"events": []' # Key difference for withdrawn: empty events
        b'}]'
    )
    expected_headers_withdrawn: Dict[str, Any] = { # Renamed
        'VULN-PUBLIC-KEY-IDENTIFIER': '7ef88907d5bba4c0120f82bfd78386a9'
                                      'd9328fb5d2d112c473ce52add3e4cd5b',
        'VULN-PUBLIC-KEY-SIGNATURE': mock.ANY,
        'Content-Type': 'application/json'
    }

    self.mock_post.assert_called_once_with(
        'https://pypi.org/_/vulnerabilities/osv/report',
        data=expected_data_withdrawn_bytes,
        headers=expected_headers_withdrawn,
        timeout=_TIMEOUT)

    actual_request_data_withdrawn: bytes = self.mock_post.call_args.kwargs['data'] # Renamed
    actual_signature_b64_withdrawn: str = self.mock_post.call_args.kwargs['headers']['VULN-PUBLIC-KEY-SIGNATURE'] # Renamed
    self._verify_signature(actual_request_data_withdrawn, actual_signature_b64_withdrawn)


if __name__ == '__main__':
  unittest.main()
