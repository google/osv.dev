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


class _ErrorReportingFilter:
  """
  A logging filter that adds necessary json fields to error logs so that they
  can be picked up by Error Reporting.
  
  https://cloud.google.com/error-reporting/docs/formatting-error-messages#log-text
  https://docs.python.org/3/howto/logging-cookbook.html#using-filters-to-impart-contextual-information
  """

  def __init__(self, service_name: str) -> None:
    self.service_name = service_name

  def filter(self, record: logging.LogRecord) -> bool:
    """Add the error reporting fields to json_fields."""
    if not hasattr(record, 'json_fields'):
      record.json_fields = {}

    if record.levelno >= logging.ERROR and not record.exc_info:
      record.json_fields.update({
          '@type':
              'type.googleapis.com/google.devtools.clouderrorreporting.v1beta1.ReportedErrorEvent',  # pylint: disable=line-too-long
          'serviceContext': {
              'service': self.service_name,
          },
          'context': {
              'reportLocation': {
                  'filePath': record.pathname,
                  'lineNumber': record.lineno,
                  'functionName': record.funcName,
              }
          },
      })

    return True


def setup_gcp_logging(service_name):
  """Set up GCP logging and error reporting."""

  logging_client = google_logging.Client()
  logging_client.setup_logging()

  logging.getLogger().addFilter(_ErrorReportingFilter(service_name))
  logging.getLogger().setLevel(logging.INFO)

  # Suppress noisy logs in some of our dependencies.
  logging.getLogger('google.api_core.bidi').setLevel(logging.ERROR)
  logging.getLogger('google.cloud.pubsub_v1.subscriber._protocol.'
                    'streaming_pull_manager').setLevel(logging.ERROR)
