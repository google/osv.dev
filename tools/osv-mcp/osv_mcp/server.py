# Copyright 2026 Google LLC
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
"""MCP server exposing the OSV.dev vulnerability database as agent tools.

Wraps the stable OSV REST API (https://api.osv.dev) as Model Context Protocol
tools so AI agents can query open source vulnerabilities directly.

Endpoints wrapped:
  - POST /v1/query       -> query_package_vulnerabilities, query_by_commit
  - POST /v1/querybatch  -> query_batch
  - GET  /v1/vulns/{id}  -> get_vulnerability

Run over stdio:
  poetry run osv-mcp            # (console script)
  poetry run python -m osv_mcp.server
"""

import os
import re
from typing import Any

import requests
from mcp.server.mcpserver import MCPServer

DEFAULT_BASE_URL = "https://api.osv.dev"
# Overridable so the server can target staging or a local API instance.
BASE_URL = os.environ.get("OSV_API_BASE_URL", DEFAULT_BASE_URL).rstrip("/")

# Network timeout (seconds) for every request to the OSV API.
REQUEST_TIMEOUT = 30

# A valid OSV id is a safe, single path segment. Validation exists purely to
# keep a crafted id from escaping the /v1/vulns/{id} path (traversal / request
# smuggling); we deliberately accept any OSV id family (GHSA-, CVE-, PYSEC-,
# OSV-, GO-, RUSTSEC-, distro prefixes, ...) rather than enumerate them.
OSV_ID_RE = re.compile(r"^[A-Za-z0-9._-]+$")

mcp = MCPServer("osv")


def _raise_for_status(resp: requests.Response) -> None:
  """Raise a readable error carrying the OSV status and a short body snippet."""
  try:
    resp.raise_for_status()
  except requests.HTTPError as exc:
    snippet = resp.text[:200].strip()
    raise requests.HTTPError(
        f"OSV API returned {resp.status_code} for {resp.url}: {snippet}",
        response=resp,
    ) from exc


def _post(path: str, payload: dict[str, Any]) -> dict[str, Any]:
  """POST JSON to the OSV API and return the decoded response."""
  resp = requests.post(
      f"{BASE_URL}{path}", json=payload, timeout=REQUEST_TIMEOUT)
  _raise_for_status(resp)
  return resp.json()


def _get(path: str) -> dict[str, Any]:
  """GET from the OSV API and return the decoded response."""
  resp = requests.get(f"{BASE_URL}{path}", timeout=REQUEST_TIMEOUT)
  _raise_for_status(resp)
  return resp.json()


@mcp.tool()
def query_package_vulnerabilities(
    package_name: str,
    ecosystem: str,
    version: str | None = None,
    page_token: str | None = None,
) -> dict[str, Any]:
  """Query OSV for vulnerabilities affecting a package.

  Args:
    package_name: Package name as used in its ecosystem (e.g. "litellm",
      "django").
    ecosystem: OSV ecosystem name (e.g. "PyPI", "npm", "Go", "Maven",
      "crates.io"). See
      https://ossf.github.io/osv-schema/#affectedpackage-field for the list.
    version: Optional exact version (e.g. "1.91.5"). When omitted, every known
      vulnerability for the package is returned regardless of version.
    page_token: Optional pagination cursor. When a response contains a
      "next_page_token", pass it here to fetch the next page.

  Returns:
    The OSV query response. The "vulns" key holds the matching advisories
    (absent or empty when the package/version is not known to be affected).
    A "next_page_token" is present when more results remain; pass it back via
    page_token to retrieve them.
  """
  query: dict[str, Any] = {
      "package": {
          "name": package_name,
          "ecosystem": ecosystem,
      }
  }
  if version is not None:
    query["version"] = version
  if page_token is not None:
    query["page_token"] = page_token
  return _post("/v1/query", query)


@mcp.tool()
def query_by_commit(commit: str,
                    page_token: str | None = None) -> dict[str, Any]:
  """Query OSV for vulnerabilities affecting a specific source commit.

  Args:
    commit: Full git commit hash to query for.
    page_token: Optional pagination cursor. When a response contains a
      "next_page_token", pass it here to fetch the next page.

  Returns:
    The OSV query response, with matching advisories under the "vulns" key.
    A "next_page_token" is present when more results remain.
  """
  query: dict[str, Any] = {"commit": commit}
  if page_token is not None:
    query["page_token"] = page_token
  return _post("/v1/query", query)


@mcp.tool()
def query_batch(queries: list[dict[str, Any]]) -> dict[str, Any]:
  """Query OSV for many packages or commits in a single batched request.

  Each query is an OSV query object, for example:
    {"package": {"name": "litellm", "ecosystem": "PyPI"}, "version": "1.91.5"}
    {"commit": "6879efc2c1596d11a6a6 ..."}

  Args:
    queries: List of OSV query objects (package+version and/or commit forms).
      At most 1000 queries per request.

  Returns:
    The batch response. "results" is a list aligned with the input "queries";
    each entry holds the "vulns" for that query (compact form — IDs and
    modified times — so call get_vulnerability for the full record).
  """
  return _post("/v1/querybatch", {"queries": queries})


@mcp.tool()
def get_vulnerability(vuln_id: str) -> dict[str, Any]:
  """Fetch the full OSV record for a single vulnerability by its ID.

  Args:
    vuln_id: An OSV vulnerability ID, e.g. "GHSA-7hp6-4w63-5g45",
      "CVE-2026-114612", or "PYSEC-2026-4322".

  Returns:
    The complete vulnerability record in OSV schema format (details, affected
    ranges, severity, references, aliases).

  Raises:
    ValueError: If vuln_id is not a syntactically valid OSV ID.
  """
  if not OSV_ID_RE.match(vuln_id) or ".." in vuln_id:
    raise ValueError(f"invalid OSV vulnerability id: {vuln_id!r}")
  return _get(f"/v1/vulns/{vuln_id}")


def main() -> None:
  """Entry point: run the MCP server over stdio transport."""
  mcp.run(transport="stdio")


if __name__ == "__main__":
  main()
