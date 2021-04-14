# Copyright 2021 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Remove duplicates and "Type, " prefixes.
CREATE TEMP FUNCTION PROCESS_LINKS(val ARRAY<STRING>) AS ((
  SELECT ARRAY_AGG(REGEXP_REPLACE(t.v, "^.*,\\s*", "") IGNORE NULLS)
  FROM (SELECT DISTINCT * FROM UNNEST(val) v) t
));

# Extract https links from package description.
CREATE TEMP FUNCTION EXTRACT_LINKS(name STRING, description STRING)
RETURNS ARRAY<STRING>
LANGUAGE js
AS r"""
if (!description) {
  return [];
}

let results = [];
for (let link of description.matchAll(/https:\/\/[A-Za-z0-9.\/#?&@=_\-]+/g)) {
  link = link[0];
  if (link.toLowerCase().includes(name.toLowerCase())) {
    // Remove trailing periods (in cases where the link is at the end of a sentence).
    results.push(link.replace(/\.$/, ''));
  }
  if (results.length >= 32) {
    break;
  }
}
return results;

""";

SELECT name,
PROCESS_LINKS(ARRAY_CONCAT(
  ARRAY_AGG(DISTINCT home_page),
  ARRAY_AGG(DISTINCT download_url),
  ARRAY_CONCAT_AGG(project_urls),
  ARRAY_CONCAT_AGG(EXTRACT_LINKS(name, description)))) as links
FROM `bigquery-public-data.pypi.distribution_metadata`
WHERE home_page is not NULL
GROUP BY name
ORDER BY name
