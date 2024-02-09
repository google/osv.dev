#!/bin/bash

set -x

# Set working dir to script dir
cd "$(dirname "$0")"

docker build -t gcr.io/oss-vdb/alpine-cve-convert -f cmd/alpine/Dockerfile .
docker build -t gcr.io/oss-vdb/combine-to-osv -f cmd/combine-to-osv/Dockerfile .
docker build -t gcr.io/oss-vdb/debian-copyright-mirror -f cmd/debian-copyright-mirror/Dockerfile .
docker build -t gcr.io/oss-vdb/cpe-repo-gen -f cmd/cpe-repo-gen/Dockerfile .

if [ "$1" = "deploy" ]
then
  docker push gcr.io/oss-vdb/alpine-cve-convert:latest
  docker push gcr.io/oss-vdb/combine-to-osv:latest
  docker push gcr.io/oss-vdb/debian-copyright-mirror:latest
  docker push gcr.io/oss-vdb/cpe-repo-gen:latest
else
  echo "Run with the deploy command to push built images"
fi
