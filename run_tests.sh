#!/bin/bash -ex

export PIPENV_IGNORE_VIRTUALENVS=1
python3 -m pipenv sync
python3 -m pipenv run python -m unittest osv.bug_test
python3 -m pipenv run python -m unittest osv.purl_helpers_test
python3 -m pipenv run python -m unittest osv.request_helper_test
python3 -m pipenv run python -m unittest osv.semver_index_test
python3 -m pipenv run python -m unittest osv.impact_git_test
python3 -m pipenv run python -m unittest osv.impact_test

# Run all osv.ecosystems tests
python3 -m pipenv run python -m unittest discover osv/ecosystems/ "*_test.py" .
