#!/bin/bash -ex

poetry install
poetry run python frontend_handlers_test.py
