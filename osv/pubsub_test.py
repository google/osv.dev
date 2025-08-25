# Copyright 2025 Google LLC
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
"""pubsub tests."""
import unittest
from unittest import mock

from . import pubsub


class PubsubTest(unittest.TestCase):
  """Pub/Sub tests."""

  @mock.patch('google.cloud.pubsub_v1.PublisherClient')
  @mock.patch('osv.utils.get_google_cloud_project')
  def test_publish_failure(self, mock_get_project, mock_publisher_client):
    """Test publish_failure."""
    mock_get_project.return_value = 'test-project'
    mock_publisher = mock.MagicMock()
    mock_publisher_client.return_value = mock_publisher

    pubsub.publish_failure(b'test data', attr1='value1')

    mock_publisher.topic_path.assert_called_once_with('test-project',
                                                      'failed-tasks')
    topic_path = mock_publisher.topic_path.return_value
    mock_publisher.publish.assert_called_once_with(
        topic_path, b'test data', attr1='value1')

  @mock.patch('osv.utils.get_google_cloud_project')
  def test_publish_failure_no_project(self, mock_get_project):
    """Test publish_failure with no project."""
    mock_get_project.return_value = ''
    with self.assertRaises(RuntimeError), self.assertLogs() as cm:
      pubsub.publish_failure(b'test data')

    self.assertEqual(
        ['ERROR:root:GOOGLE_CLOUD_PROJECT not set, cannot send retry message'],
        cm.output)


if __name__ == '__main__':
  unittest.main()
