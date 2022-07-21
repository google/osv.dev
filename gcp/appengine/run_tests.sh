#!/bin/bash -ex

python3 -m pipenv sync
python3 -m pipenv run python frontend_handlers_test.py
