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
"""OSV cron handlers."""

# TODO(michaelkedar): Cloud Run equivalents need to be made for these.
# This cron logic should probably be removed from the website entirely.
# https://github.com/google/osv.dev/issues/1249

from flask import Blueprint
from flask import send_file, send_from_directory

blueprint = Blueprint('handlers', __name__)


# TODO(michaelkedar): Cloud Run is currently using this its health checks.
# Should replace this with the conventional /healthz endpoint.
@blueprint.route('/_ah/warmup')
def warmup():
  """Warmup handler."""
  return 'OK'


@blueprint.route('/public_keys/<path:filename>')
def public_keys(filename):
  """Public keys handler."""
  return send_from_directory(
      'dist/public_keys', filename, mimetype='text/plain')


@blueprint.route('/docs/osv_service_v1.swagger.json')
def swagger():
  """Swagger file handler."""
  return send_file('docs/osv_service_v1.swagger.json')
