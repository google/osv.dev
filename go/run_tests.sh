#!/bin/bash -ex

go test ./...

# Verify sqlc generated files are up to date
(cd ./internal/database/postgres && go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.31.1 diff)

