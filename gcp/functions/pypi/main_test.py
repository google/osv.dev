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
import base64
import os
import unittest
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import ECDSA
from cryptography.hazmat.primitives.hashes import SHA256

import main

_TEST_DATA_DIR = 'testdata'


def _load_test_data(name):
  """Load test data."""
  with open(os.path.join('testdata', name), 'rb') as f:
    return f.read()


_TEST_VULN = _load_test_data("test_vuln.json")
_FAKE_SECRET = _load_test_data("fake_secret.json")
_FAKE_PUB_KEY = _load_test_data("fake_pub_key.pem")


class PublishPyPiTest(unittest.TestCase):
  """Tests for publish_pypi."""

  def setUp(self):
    patcher = mock.patch(
        'google.cloud.secretmanager.SecretManagerServiceClient')
    mock_secret_client = patcher.start()
    self.addCleanup(patcher.stop)

    mock_secret = mock.MagicMock()
    mock_secret.payload.data = _FAKE_SECRET
    mock_secret_client().access_secret_version.return_value = mock_secret

    patcher = mock.patch('requests.post')
    self.mock_post = patcher.start()
    self.addCleanup(patcher.stop)

  def _verify_signature(self, request, signature):
    """Verify signature."""
    public_key = serialization.load_pem_public_key(data=_FAKE_PUB_KEY)
    public_key.verify(
        signature=base64.b64decode(signature),
        data=request,
        signature_algorithm=ECDSA(algorithm=SHA256()),
    )

  def test_publish(self):
    """Test publishing."""
    event = {
        'data': base64.b64encode(_TEST_VULN),
    }

    main.publish(event, None)
    self.mock_post.assert_called_once_with(
        'https://pypi.org/_/vulnerabilities/osv/report',
        data=b'[{"id": "PYSEC-2021-63", "project": "cryptography", '
        b'"versions": ["3.1", "3.1.1", "3.2", "3.2.1", "3.3", "3.3.1"], '
        b'"link": "https://osv.dev/vulnerability/PYSEC-2021-63", '
        b'"aliases": ["CVE-2020-36242"]}]',
        headers={
            'VULN-PUBLIC-KEY-IDENTIFIER': '7ef88907d5bba4c0120f82bfd78386a9'
                                          'd9328fb5d2d112c473ce52add3e4cd5b',
            'VULN-PUBLIC-KEY-SIGNATURE': mock.ANY
        })

    request = self.mock_post.call_args.kwargs['data']
    signature = self.mock_post.call_args.kwargs['headers'][
        'VULN-PUBLIC-KEY-SIGNATURE']
    self._verify_signature(request, signature)


if __name__ == '__main__':
  unittest.main()
