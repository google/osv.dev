#!/bin/bash -ex

export PIPENV_IGNORE_VIRTUALENVS=1
set +x  # Keep the API key out of execution logs
# Temporarily confirm that we're getting expected output
kubectl get secret secrets
export DEPSDEV_API_KEY=$(kubectl get secret secrets -o jsonpath='{.data.deps\.dev}' | base64 --decode)
set -x
python3 -m pipenv sync
python3 -m pipenv run python -m unittest osv.bug_test
python3 -m pipenv run python -m unittest osv.ecosystems_test
python3 -m pipenv run python -m unittest osv.maven.version_test
python3 -m pipenv run python -m unittest osv.nuget_test
python3 -m pipenv run python -m unittest osv.purl_helpers_test
python3 -m pipenv run python -m unittest osv.request_helper_test
