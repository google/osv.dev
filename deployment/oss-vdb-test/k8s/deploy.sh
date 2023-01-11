#!/bin/bash

UPSTREAM_URL="https://github.com/google/osv.dev"
UPSTREAM_REMOTE_NAME="upstream-release"

# Return if the deployment time is suboptimal
oss_fuzz_time() {
  # http://go/osv-deploy says not to deploy between 12am and 3am
  current_hour=$(TZ=Australia/Sydney date +%-H) # '-' to remove leading 0 which will be parsed as hex
  if [[ $current_hour -ge 0 && $current_hour -lt 3 ]]; then
    return 1
  fi
  return 0
}

if [ $# -lt 1 ]; then
  echo "Usage: $0 <commit-sha>"
  exit 1
fi

if ! oss_fuzz_time && ! [ -n "$FORCE" ]; then
  echo "Now is not an advisable time to deploy, see http://go/osv-deploy"
  exit 1
fi

git remote add $UPSTREAM_REMOTE_NAME $UPSTREAM_URL
git fetch $UPSTREAM_REMOTE_NAME

if git diff --quiet $UPSTREAM_REMOTE_NAME/master || [ -n "$FORCE" ]; then
  git remote remove $UPSTREAM_REMOTE_NAME
  gcloud beta builds submit . --project=oss-vdb-test --substitutions=COMMIT_SHA=$1
else
  git remote remove $UPSTREAM_REMOTE_NAME
  echo 'You need to be on the latest master.'
fi
