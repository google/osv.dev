#!/bin/bash -ex

dir=$(dirname "$0")

if [ $# -lt 1 ]; then
  echo "Usage: $0 <project-id> <version-tag> <path-to-yaml-configs> ..args.."
  exit 1
fi

project_id=$1
shift

version=$1
shift

# `gcloud app deploy` requires that the app.yaml file lives in the application
# root (i.e. the directory containing this script). We'll symlink in all
# relevant yaml files from the given config dir here.
configs_dir=$1
shift

for config in $configs_dir/*.yaml; do
  ln -sf $(realpath "$config") $dir/$(basename "$config")
done

cd "$dir"
image="gcr.io/$project_id/osv-website"

if [ -z "$CLOUDBUILD" ]; then
  pushd ../../
  # Using BuildKit allows us to cache the multi-stage builds
  DOCKER_BUILDKIT=1 docker build --build-arg=BUILDKIT_INLINE_CACHE=1 -t $image:$version -f gcp/appengine/Dockerfile --cache-from=$image .
  docker push $image:$version
  popd
fi

gcloud app deploy --quiet --project=$project_id --version=$version --image-url=$image:$version "$@"
