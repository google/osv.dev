#!/bin/bash -ex

export PIPENV_IGNORE_VIRTUALENVS=1
python3 -m pipenv sync
python3 -m pipenv run python frontend_handlers_test.py
