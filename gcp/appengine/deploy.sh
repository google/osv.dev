#!/bin/bash -ex

if [ $# -lt 1 ]; then
  echo "Usage: $0 <path to app.yaml> ..args.."
  exit 1
fi

pushd frontend3
npm install
npm run build:prod
popd

# Skip the '-e' editable library install as we copy in the "osv" library
# directly instead for deployment.
python3 -m pipenv requirements | grep -v '^-e '  > requirements.txt
gcloud app deploy --quiet --project=oss-vdb --version=$(git rev-parse HEAD) "$@"
