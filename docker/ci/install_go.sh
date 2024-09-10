#!/bin/bash
# Copyright 2022 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

set -eux

# Download and install Go
# https://pkg.go.dev/golang.org/x/tools/cmd/getgo#section-readme
curl -LO https://get.golang.org/$(uname)/go_installer && chmod +x go_installer && SHELL="bash" ./go_installer -version 1.23.1 && rm go_installer
