#!/bin/bash -ex

if [ "$USE_POETRY" == "true" ]
then
  poetry install
  poetry run python frontend_handlers_test.py
  exit 0
fi

export PIPENV_IGNORE_VIRTUALENVS=1
python3 -m pipenv sync
python3 -m pipenv run python frontend_handlers_test.py
