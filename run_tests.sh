#!/bin/bash -ex

export PIPENV_IGNORE_VIRTUALENVS=1
poetry install
poetry run python -m unittest osv.bug_test
poetry run python -m unittest osv.purl_helpers_test
poetry run python -m unittest osv.request_helper_test
poetry run python -m unittest osv.semver_index_test
poetry run python -m unittest osv.impact_test

# Run all osv.ecosystems tests
poetry run python -m unittest discover osv/ecosystems/ "*_test.py" .
