# Copyright 2025 Google LLC
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
"""OSV MCP server implementation."""

import argparse
import logging
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP

DEFAULT_API_ENDPOINT = "https://api.osv.dev"

logger = logging.getLogger(__name__)

mcp = FastMCP("osv-mcp")

# Initialize api_endpoint with default value
api_endpoint = DEFAULT_API_ENDPOINT
_http_session = None


def get_http_session():
  """
  Get or create the HTTP session for connecting to the API server.
  """
  global _http_session

  if _http_session is None:
    _http_session = requests.Session()
    _http_session.headers.update({
        "Content-Type": "application/json",
        "User-Agent": "OSV-MCP-Server/1.0"
    })

  return _http_session


def safe_http_call(call_func, error_prefix: str = "Error") -> dict[str, Any]:
  """
  Safely execute an HTTP call and return the result as a dict.
  """
  try:
    response = call_func()
    response.raise_for_status()
    return response.json()
  except requests.exceptions.HTTPError as e:
    error_msg = (f"{error_prefix}: HTTP {e.response.status_code}: "
                 f"{e.response.text}")
    logger.error(error_msg)
    return {"error": error_msg}
  except requests.exceptions.RequestException as e:
    error_msg = f"{error_prefix}: {str(e)}"
    logger.error(error_msg)
    return {"error": error_msg}
  except Exception as e:
    error_msg = f"{error_prefix}: {str(e)}"
    logger.error(error_msg)
    return {"error": error_msg}


@mcp.tool()
def get_vulnerability_by_id(vuln_id: str) -> dict[str, Any]:
  """
  Get a vulnerability by its OSV ID.

  Retrieves complete vulnerability information including affected packages,
  severity, references, and remediation details.

  Args:
      vuln_id: The OSV vulnerability ID (e.g., "GHSA-xxxx-xxxx-xxxx" or
               "CVE-2024-1234")

  Returns:
      Dictionary with vulnerability details or error message.

  Example:
      get_vulnerability_by_id("CVE-2024-1234")
  """
  if not vuln_id:
    return {"error": "vuln_id is required"}

  if len(vuln_id) > 100:
    return {"error": "ID too long (max 100 characters)"}

  session = get_http_session()
  url = f"{api_endpoint}/v1/vulns/{vuln_id}"

  return safe_http_call(lambda: session.get(url),
                        f"Error getting vulnerability {vuln_id}")


@mcp.tool()
def query_affected(package_name: str = "",
                   ecosystem: str = "",
                   version: str = "",
                   commit: str = "",
                   purl: str = "",
                   page_token: str = "") -> dict[str, Any]:
  """
  Query vulnerabilities affecting a specific package, version, or commit.

  Search for known vulnerabilities that affect a package at a given version
  or commit hash. Can query by package name + ecosystem, commit hash, or PURL.

  Args:
      package_name: Package name (e.g., "django", "lodash")
      ecosystem: Ecosystem (e.g., "PyPI", "npm", "Go", "Maven")
      version: Version to check (e.g., "1.2.3")
      commit: Git commit hash (alternative to package/version)
      purl: Package URL format (alternative to package_name/ecosystem)
      page_token: Token for pagination (from previous response)

  Returns:
      Dictionary with list of vulnerabilities and pagination info.

  Examples:
      query_affected(package_name="django", ecosystem="PyPI", version="3.2.0")
      query_affected(commit="abc123def456...")
      query_affected(purl="pkg:pypi/django@3.2.0")
  """
  # Build the query JSON
  query = {}

  if commit:
    query["commit"] = commit
  elif purl:
    query["package"] = {"purl": purl}
    if version:
      query["version"] = version
  elif package_name:
    package_obj = {"name": package_name}
    if ecosystem:
      package_obj["ecosystem"] = ecosystem
    query["package"] = package_obj
    if version:
      query["version"] = version
  else:
    return {"error": "Must provide either commit, purl, or package_name"}

  if page_token:
    query["page_token"] = page_token

  session = get_http_session()
  url = f"{api_endpoint}/v1/query"

  return safe_http_call(lambda: session.post(url, json=query),
                        "Error querying affected packages")


@mcp.tool()
def query_affected_batch(queries: list[dict[str, str]]) -> dict[str, Any]:
  """
  Batch query vulnerabilities for multiple packages/versions/commits.

  Query multiple packages or commits in a single request for better efficiency.
  Maximum 1000 queries per batch.

  Args:
      queries: List of query dictionaries, each containing:
          - package_name: Package name (optional)
          - ecosystem: Ecosystem (optional)
          - version: Version (optional)
          - commit: Git commit hash (optional)
          - purl: Package URL (optional)
          - page_token: Pagination token (optional)

  Returns:
      Dictionary with list of results (one per query).

  Example:
      query_affected_batch([
          {"package_name": "django", "ecosystem": "PyPI", "version": "3.2.0"},
          {"package_name": "flask", "ecosystem": "PyPI", "version": "1.1.0"}
      ])
  """
  if not queries:
    return {"error": "queries list is required"}

  if len(queries) > 1000:
    return {"error": "Too many queries (max 1000)"}

  # Build batch query JSON
  batch_queries = []

  for query_dict in queries:
    query = {}

    if "commit" in query_dict and query_dict["commit"]:
      query["commit"] = query_dict["commit"]
    elif "purl" in query_dict and query_dict["purl"]:
      query["package"] = {"purl": query_dict["purl"]}
      if "version" in query_dict and query_dict["version"]:
        query["version"] = query_dict["version"]
    elif "package_name" in query_dict and query_dict["package_name"]:
      package_obj = {"name": query_dict["package_name"]}
      if "ecosystem" in query_dict and query_dict["ecosystem"]:
        package_obj["ecosystem"] = query_dict["ecosystem"]
      query["package"] = package_obj
      if "version" in query_dict and query_dict["version"]:
        query["version"] = query_dict["version"]

    if "page_token" in query_dict and query_dict["page_token"]:
      query["page_token"] = query_dict["page_token"]

    batch_queries.append(query)

  session = get_http_session()
  url = f"{api_endpoint}/v1/querybatch"
  payload = {"queries": batch_queries}

  return safe_http_call(lambda: session.post(url, json=payload),
                        "Error in batch query")


@mcp.tool()
def determine_version(file_hashes: list[dict[str, str]],
                      name: str = "") -> dict[str, Any]:
  """
  Determine the version of a project based on file hashes.

  Analyzes MD5 file hashes to identify potential versions/releases that match
  the provided files. Useful for determining what version of a library you have.

  Args:
      file_hashes: List of file hash dictionaries, each with:
          - hash: MD5 hash as hex string (required)
          - file_path: Relative file path (optional)
      name: Dependency name (optional)

  Returns:
      Dictionary with list of version matches sorted by score.

  Example:
      determine_version(
          file_hashes=[
              {"hash": "a1b2c3d4...", "file_path": "src/main.py"},
              {"hash": "e5f6g7h8...", "file_path": "lib/utils.js"}
          ],
          name="my-project"
      )
  """
  if not file_hashes:
    return {"error": "file_hashes list is required"}

  if len(file_hashes) > 10000:
    return {"error": "Too many file hashes (max 10000)"}

  # Build version query JSON
  version_query = {}
  if name:
    version_query["name"] = name

  hash_list = []
  for file_hash_dict in file_hashes:
    if "hash" not in file_hash_dict:
      continue

    hash_obj = {"hash": file_hash_dict["hash"]}

    # Optional file path
    if "file_path" in file_hash_dict:
      hash_obj["path"] = file_hash_dict["file_path"]

    # Hash type defaults to MD5 (value 1 in the protobuf enum)
    hash_obj["type"] = 1

    hash_list.append(hash_obj)

  if not hash_list:
    return {"error": "No valid file hashes provided"}

  version_query["file_hashes"] = hash_list

  session = get_http_session()
  url = f"{api_endpoint}/v1/determineversion"

  return safe_http_call(lambda: session.post(url, json=version_query),
                        "Error determining version")


def cleanup():
  """Cleanup HTTP session on shutdown."""
  global _http_session
  if _http_session:
    _http_session.close()
    _http_session = None


def main():
  """Main entry point for the OSV MCP server."""
  parser = argparse.ArgumentParser(description="OSV MCP Server")
  parser.add_argument(
      "--api-endpoint",
      type=str,
      default=DEFAULT_API_ENDPOINT,
      help=f"OSV API endpoint URL, default: {DEFAULT_API_ENDPOINT}")
  parser.add_argument(
      "--mcp-host",
      type=str,
      default="127.0.0.1",
      help="Host to run MCP server on (only for SSE transport), "
      "default: 127.0.0.1")
  parser.add_argument(
      "--mcp-port",
      type=int,
      default=8001,
      help="Port to run MCP server on (only for SSE transport), "
      "default: 8001")
  parser.add_argument(
      "--transport",
      type=str,
      default="stdio",
      choices=["stdio", "sse"],
      help="Transport protocol for MCP, default: stdio")
  parser.add_argument(
      "--log-level",
      type=str,
      default="INFO",
      choices=["DEBUG", "INFO", "WARNING", "ERROR"],
      help="Logging level, default: INFO")

  args = parser.parse_args()

  # Update global API endpoint
  global api_endpoint
  if args.api_endpoint:
    api_endpoint = args.api_endpoint

  # Set up logging
  log_level = getattr(logging, args.log_level)
  logging.basicConfig(
      level=log_level,
      format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')

  if args.transport == "sse":
    try:
      # Configure MCP for SSE
      mcp.settings.log_level = args.log_level
      mcp.settings.host = args.mcp_host
      mcp.settings.port = args.mcp_port

      logger.info("Connecting to OSV API at %s", api_endpoint)
      logger.info("Starting MCP server on http://%s:%s/sse", mcp.settings.host,
                  mcp.settings.port)
      logger.info("Using transport: %s", args.transport)

      mcp.run(transport="sse")
    except KeyboardInterrupt:
      logger.info("Server stopped by user")
      cleanup()
  else:
    # stdio mode (for use with MCP clients)
    logger.info("Connecting to OSV API at %s", api_endpoint)
    logger.info("Starting MCP server with stdio transport")

    try:
      mcp.run()
    except KeyboardInterrupt:
      logger.info("Server stopped by user")
      cleanup()


if __name__ == "__main__":
  main()
