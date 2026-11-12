#!/bin/bash -ex

if [ -n "$CI" ]; then
  go test ./... -coverprofile=coverage.out
else
  go test ./...
fi

# Verify sqlc generated files are up to date
(cd ./internal/database/postgres && go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 diff)


