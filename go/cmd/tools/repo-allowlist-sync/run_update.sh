#!/bin/bash -ex

go run . --project=oss-vdb --file=repo_allowlist.yaml --dry-run=false --verbose=true
go run . --project=oss-vdb-test --file=repo_allowlist_test.yaml --dry-run=false --verbose=true
