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
"""Pub/Sub helpers."""
import logging

from google.cloud import pubsub_v1

from . import utils

FAILED_TASKS_TOPIC = 'failed-tasks'
_pubsub_client = None


def _get_pubsub_client() -> pubsub_v1.PublisherClient:
  """Get a Pub/Sub publisher client."""
  global _pubsub_client
  if _pubsub_client is None:
    _pubsub_client = pubsub_v1.PublisherClient()
  return _pubsub_client


def publish_failure(data: bytes, **attributes: str):
  """Publishes a message to the failed-tasks topic."""
  project = utils.get_google_cloud_project()
  if not project:
    logging.error('GOOGLE_CLOUD_PROJECT not set, cannot send retry message')
    raise RuntimeError('GOOGLE_CLOUD_PROJECT not set')

  publisher = _get_pubsub_client()
  topic = publisher.topic_path(project, FAILED_TASKS_TOPIC)

  try:
    publisher.publish(topic, data, **attributes)
    logging.info('Published failure message to %s with attributes %s', topic,
                 attributes)
  except Exception:
    logging.exception('Failed to publish failure message to %s', topic)
    raise
