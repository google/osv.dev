# Copyright 2023 Google LLC
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
"""GCP Logging Helpers."""

import logging
from google.cloud import logging as google_logging


def setup_gcp_logging(service_name):
  """Set up GCP logging and error reporting."""

  logging_client = google_logging.Client()
  logging_client.setup_logging()

  old_factory = logging.getLogRecordFactory()

  def record_factory(*args, **kwargs):
    """Insert jsonPayload fields to all logs."""

    record = old_factory(*args, **kwargs)
    if not hasattr(record, 'json_fields'):
      record.json_fields = {}

    # Add jsonPayload fields to logs that don't contain stack traces to enable
    # capturing and grouping by error reporting.
    # https://cloud.google.com/error-reporting/docs/formatting-error-messages#log-text
    if record.levelno >= logging.ERROR and not record.exc_info:
      record.json_fields.update({
          '@type':
              'type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent',  # pylint: disable=line-too-long
          'serviceContext': {
              'service': service_name,
          },
          'context': {
              'reportLocation': {
                  'filePath': record.pathname,
                  'lineNumber': record.lineno,
                  'functionName': record.funcName,
              }
          },
      })

    return record

  logging.setLogRecordFactory(record_factory)
  logging.getLogger().setLevel(logging.INFO)

  # Suppress noisy logs in some of our dependencies.
  logging.getLogger('google.api_core.bidi').setLevel(logging.ERROR)
  logging.getLogger('google.cloud.pubsub_v1.subscriber._protocol.'
                    'streaming_pull_manager').setLevel(logging.ERROR)

  # Suppress OSS-Fuzz build error logs. These are expected as part of
  # bisection.
  logging.getLogger('helper').setLevel(logging.CRITICAL)
