# Build the Javascript frontend
FROM node:latest AS FRONTEND3_BUILD
WORKDIR /build/frontend3

# Install dependencies first for better caching
COPY gcp/appengine/frontend3/package.json gcp/appengine/frontend3/package-lock.json ./
RUN npm ci

COPY gcp/appengine/frontend3/webpack.prod.js ./
COPY gcp/appengine/frontend3/img img
COPY gcp/appengine/frontend3/src src

RUN npm run build:prod

# Build hugo blogs
FROM golang:1.20 AS HUGO_BUILD
# Build hugo from source - this should usually be cached.
RUN go install -tags extended github.com/gohugoio/hugo@v0.111.3

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
COPY setup.py Pipfile* README.md /osv/
COPY osv /osv/osv
COPY gcp/appengine/Pipfile* ./
RUN pip3 install -U pipenv==2023.6.12 && python3 -m pipenv install --deploy --system

# Website Python code
COPY gcp/appengine/*.py ./

# JS/hugo builds
COPY gcp/appengine/dist/public_keys dist/public_keys
COPY gcp/appengine/docs docs
COPY --from=FRONTEND3_BUILD --link /build/dist/ dist/
COPY --from=HUGO_BUILD --link /build/dist dist/


# Run the web service on container startup. Here we use the gunicorn
# webserver, with 4 worker processes and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
CMD exec gunicorn --bind :$PORT --workers 4 --threads 8 --timeout 0 main:app
