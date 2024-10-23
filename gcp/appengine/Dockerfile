# Build the Javascript frontend
FROM node:20.18@sha256:a5e0ed56f2c20b9689e0f7dd498cac7e08d2a3a283e92d9304e7b9b83e3c6ff3 AS FRONTEND3_BUILD
WORKDIR /build/frontend3

# Install dependencies first for better caching
COPY gcp/appengine/frontend3/package.json gcp/appengine/frontend3/package-lock.json ./
RUN npm ci

COPY gcp/appengine/frontend3/webpack.prod.js ./
COPY gcp/appengine/frontend3/img img
COPY gcp/appengine/frontend3/src src

RUN npm run build:prod

# Build hugo blogs
# Use the ci image, since it already built the version of hugo we want from source
FROM gcr.io/oss-vdb/ci AS HUGO_BUILD

WORKDIR /build/blog
COPY gcp/appengine/blog ./

RUN hugo --buildFuture -d ../dist/static/blog

# OSV.dev site image
# Adapted from https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service#writing
FROM python:3.11-slim@sha256:ad5dadd957a398226996bc4846e522c39f2a77340b531b28aaab85b2d361210b

# Generation 1 of cloud run overrides the HOME environment variable, causing
# poetry to run in the incorrect environment, as it defaults to using $HOME/.cache/virtualenvs/...
# 
# This forces it to create the virtualenv in the same directory as the project, avoiding this issue.
ENV POETRY_VIRTUALENVS_IN_PROJECT=true

# Allow statements and log messages to immediately appear in the logs
ENV PYTHONUNBUFFERED True
WORKDIR /osv/gcp/appengine

# Install Python dependencies
COPY setup.py poetry.lock pyproject.toml README.md /osv/
COPY osv /osv/osv
COPY gcp/appengine/poetry.lock gcp/appengine/pyproject.toml ./
RUN pip3 install poetry==1.8.3 && poetry install

# Website Python code
COPY gcp/appengine/*.py ./

# JS/hugo builds
COPY gcp/appengine/dist/public_keys dist/public_keys
COPY gcp/appengine/docs docs
# gcp/appengine/docs/docs/osv_service_v1.swagger.json is a symlink
COPY docs/osv_service_v1.swagger.json docs/

COPY --from=FRONTEND3_BUILD /build/dist/ dist/
COPY --from=HUGO_BUILD /build/dist dist/

RUN poetry run python -m whitenoise.compress dist/static/

# Run the web service on container startup. Here we use the gunicorn
# webserver, with one worker process and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
CMD poetry run gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app
