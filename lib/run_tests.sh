#!/bin/bash -ex

unset PIP_NO_BINARY
pipenv sync
pipenv run python -m unittest osv.bug_test
pipenv run python -m unittest osv.ecosystems_test
pipenv run python -m unittest osv.maven.version_test
pipenv run python -m unittest osv.nuget_test
