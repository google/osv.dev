#!/bin/bash
cd "$(dirname "$0")"
poetry install
exec poetry run python server.py "$@"