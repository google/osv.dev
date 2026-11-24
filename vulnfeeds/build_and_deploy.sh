#!/bin/bash

set -x

# Set working dir to script dir
cd "$(dirname "$0")"

docker build -t gcr.io/oss-vdb/alpine-cve-convert --target alpine-cve-convert -f Dockerfile .
docker build -t gcr.io/oss-vdb/debian-cve-convert --target debian-cve-convert -f Dockerfile .
docker build -t gcr.io/oss-vdb/combine-to-osv --target combine-to-osv -f Dockerfile .
docker build -t gcr.io/oss-vdb/debian-copyright-mirror --target debian-copyright-mirror -f Dockerfile .
docker build -t gcr.io/oss-vdb/cpe-repo-gen --target cpe-repo-gen -f Dockerfile .

if [ "$1" = "deploy" ]
then
  docker push gcr.io/oss-vdb/alpine-cve-convert:latest
  docker push gcr.io/oss-vdb/debian-cve-convert:latest
  docker push gcr.io/oss-vdb/combine-to-osv:latest
  docker push gcr.io/oss-vdb/debian-copyright-mirror:latest
  docker push gcr.io/oss-vdb/cpe-repo-gen:latest
else
  echo "Run with the deploy command to push built images"
fi
