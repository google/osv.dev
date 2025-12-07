#!/bin/bash -ex

export GOOGLE_CLOUD_PROJECT=fake-project123

poetry install
poetry run python frontend_handlers_test.py
