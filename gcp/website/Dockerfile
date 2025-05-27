# Build the Javascript frontend
FROM node:20.19@sha256:7c4cd7c6935554b79c6fffb88e7bde3db0ce25b45d4c634d1fb0f1a6e7f5b782 AS FRONTEND3_BUILD
WORKDIR /build/frontend3

# Install dependencies first for better caching
COPY gcp/website/frontend3/package.json gcp/website/frontend3/package-lock.json ./
RUN npm ci

COPY gcp/website/frontend3/webpack.prod.js ./
COPY gcp/website/frontend3/img img
COPY gcp/website/frontend3/src src

RUN npm run build:prod

# Build hugo blogs
# Use the ci image, since it already built the version of hugo we want from source
FROM gcr.io/oss-vdb/ci AS HUGO_BUILD

WORKDIR /build/blog
COPY gcp/website/blog ./

RUN hugo --buildFuture -d ../dist/static/blog

# OSV.dev site image
# Adapted from https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service#writing
FROM python:3.12.8-slim@sha256:8859bd6ca943079262c27e38b7119cdacede77c463139a15651dd340087a6cc9

# Generation 1 of cloud run overrides the HOME environment variable, causing
# poetry to run in the incorrect environment, as it defaults to using $HOME/.cache/virtualenvs/...
# 
# This forces it to create the virtualenv in the same directory as the project, avoiding this issue.
ENV POETRY_VIRTUALENVS_IN_PROJECT=true
ENV POETRY_HOME "/opt/poetry"
COPY docker/poetry/requirements.txt ./poetry-requirements.txt
RUN python3 -m venv $POETRY_HOME && \
    $POETRY_HOME/bin/pip install --require-hashes -r ./poetry-requirements.txt && \
    ln -s $POETRY_HOME/bin/poetry /usr/local/bin/poetry

# Allow statements and log messages to immediately appear in the logs
ENV PYTHONUNBUFFERED True
WORKDIR /osv/gcp/website

# Install Python dependencies
COPY poetry.lock pyproject.toml README.md /osv/
COPY osv /osv/osv
COPY gcp/website/poetry.lock gcp/website/pyproject.toml ./
RUN poetry install

# Website Python code
COPY gcp/website/*.py ./

# JS/hugo builds
COPY gcp/website/dist/public_keys dist/public_keys
COPY gcp/website/docs docs
# gcp/website/docs/docs/osv_service_v1.swagger.json is a symlink
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
