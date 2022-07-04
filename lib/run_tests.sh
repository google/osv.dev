#!/bin/bash -ex

unset PIP_NO_BINARY
python -m pipenv sync
python -m pipenv run python -m unittest osv.bug_test
python -m pipenv run python -m unittest osv.ecosystems_test
python -m pipenv run python -m unittest osv.maven.version_test
python -m pipenv run python -m unittest osv.nuget_test
python -m pipenv run python -m unittest osv.purl_helpers_test
