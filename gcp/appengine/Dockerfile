# Build the Javascript frontend
FROM node:20.9 AS FRONTEND3_BUILD
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

RUN hugo -d ../dist/static/blog

# OSV.dev site image
# Adapted from https://cloud.google.com/run/docs/quickstarts/build-and-deploy/deploy-python-service#writing
FROM python:3.11-slim

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
