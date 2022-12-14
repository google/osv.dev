#!/bin/bash -ex

dir=$(dirname "$0")

if [ $# -lt 1 ]; then
  echo "Usage: $0 <project-id> <path-to-yaml-configs> ..args.."
  exit 1
fi

project_id=$1
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

pushd frontend3
npm install
npm run build:prod
popd

pushd blog
hugo -d ../dist/static/blog
popd

# Skip the '-e' editable library install as we copy in the "osv" library
# directly instead for deployment.
python3 -m pipenv requirements | grep -v '^-e '  > requirements.txt
gcloud app deploy --quiet --project=$project_id --version=$(git rev-parse HEAD) "$@"
