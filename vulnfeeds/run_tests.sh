#!/bin/bash

echo !!!
echo !!! FYI external IP is: $(curl -s https://ipinfo.io/ip)
echo !!!

set -e

go test ./...
