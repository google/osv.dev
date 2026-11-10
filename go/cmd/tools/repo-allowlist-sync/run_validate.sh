#!/bin/bash -ex

go run . --file=repo_allowlist.yaml --validate
go run . --file=repo_allowlist_test.yaml --validate
