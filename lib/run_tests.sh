#!/bin/bash -ex

unset PIP_NO_BINARY
python3 -m pipenv sync
python3 -m pipenv run python -m unittest osv.bug_test
python3 -m pipenv run python -m unittest osv.ecosystems_test
python3 -m pipenv run python -m unittest osv.maven.version_test
python3 -m pipenv run python -m unittest osv.nuget_test
python3 -m pipenv run python -m unittest osv.purl_helpers_test
