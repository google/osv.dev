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

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <tag>"
  exit 1
fi

if ! oss_fuzz_time && ! [[ -n "$FORCE" ]]; then
  echo "Now is not an advisable time to deploy, see http://go/osv-deploy"
  exit 1
fi

# Check upstream url master by creating a temporary remote.
git remote add "$UPSTREAM_REMOTE_NAME" "$UPSTREAM_URL"
git fetch "$UPSTREAM_REMOTE_NAME" --quiet

tag_name="$1"
commit_sha="$(git rev-parse --verify $tag_name)"
short_sha="$(git rev-parse --short=7 $tag_name)"

git remote remove "$UPSTREAM_REMOTE_NAME"

if [[ -z "$commit_sha" || -z "$short_sha" ]]; then
  echo "Unable to resolve commit for the tag $tag_name"
  exit 1
fi

gcloud beta builds submit --config=deploy-prod.yaml --project=oss-vdb --no-source --substitutions="COMMIT_SHA=${commit_sha},SHORT_SHA=${short_sha},TAG_NAME=${tag_name}"
