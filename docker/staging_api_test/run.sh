#!/bin/bash -x
# Copyright 2024 Google LLC
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

python3 ./retrieve_bugs_from_db.py

# `aiohttp` has limits on the number of simultaneous connections.
# Running two instances of the program in parrallel 
# can help circumvent this restriction.
python3 ./perform_api_calls.py &
python3 ./perform_api_calls.py &

# Wait for both background processes to finish
wait