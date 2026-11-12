#!/bin/bash -ex

if [ -n "$CI" ]; then
  go test ./... -coverprofile=coverage.out
else
  go test ./...
fi


