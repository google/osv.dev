#!/bin/bash -ex

pipenv sync
pipenv run python -m unittest osv.bug_test
pipenv run python -m unittest osv.ecosystems_test
