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
"""Website entrypoint."""

import logging

from flask import Flask
from flask_compress import Compress
import google.cloud.logging
from google.cloud import ndb
from whitenoise import WhiteNoise

import cache
import frontend_handlers
import handlers
import utils

ndb_client = ndb.Client()


def ndb_wsgi_middleware(wsgi_app):
  """WSGI middleware for ndb_datastore context allocation to the app."""

  def middleware(environ, start_response):
    with ndb_client.context():
      return wsgi_app(environ, start_response)

  return middleware


def create_app():
  """Create flask app."""
  if utils.is_prod():
    logging_client = google.cloud.logging.Client()
    logging_client.setup_logging()

  logging.getLogger().setLevel(logging.INFO)

  flask_app = Flask(
      __name__, template_folder='dist', static_folder='dist/static')
  flask_app.register_blueprint(handlers.blueprint)
  flask_app.register_blueprint(frontend_handlers.blueprint)
  flask_app.config['TEMPLATES_AUTO_RELOAD'] = True
  flask_app.config['COMPRESS_MIMETYPES'] = ['text/html']

  flask_app.wsgi_app = ndb_wsgi_middleware(flask_app.wsgi_app)
  flask_app.wsgi_app = WhiteNoise(
      flask_app.wsgi_app,
      root='dist/static/',
      prefix='static',
      max_age=60 * 60 * 24)

  cache.instance.init_app(flask_app)
  compress = Compress()
  compress.init_app(flask_app)
  return flask_app


app = create_app()

if __name__ == '__main__':
  app.run(host='127.0.0.1', port=8000, debug=False)
