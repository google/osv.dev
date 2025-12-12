#!/bin/bash -ex

go test ./...

# Run the validation for the go/python datastore models
cd ./osv/models/internal/validate/ && ./run_validate.sh
