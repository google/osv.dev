#!/bin/bash -ex

if [ -n "$CI" ]; then
  cd go && go test ./... -coverprofile=coverage.out
else
  cd go && go test ./...
fi

