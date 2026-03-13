#!/bin/bash -ex

go test ./...

# Run the validation for the go/python datastore models
cd ./internal/database/datastore/internal/validate/ && ./run_validate.sh
