#!/bin/bash

# Return if the deployment time is suboptimal
oss_fuzz_time() {
  # http://go/osv-deploy says not to deploy between 12am and 3am
  current_hour=$(TZ=Australia/Sydney date +%H)
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

git fetch
if git diff --quiet origin/main || [ -n "$FORCE" ]; then
  gcloud beta builds submit . --project=oss-vdb-test --substitutions=COMMIT_SHA=$1
else
  echo 'You need to be on origin/main.'
fi
