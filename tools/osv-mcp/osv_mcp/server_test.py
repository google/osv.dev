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
"""Tests for the OSV MCP server tools (HTTP mocked, no network)."""

import unittest

import responses

from osv_mcp import server

BASE = server.BASE_URL


class QueryPackageVulnerabilitiesTest(unittest.TestCase):
  """Tests for query_package_vulnerabilities."""

  @responses.activate
  def test_with_version(self):
    """A version query includes the version and ecosystem in the body."""
    responses.post(
        f"{BASE}/v1/query",
        json={"vulns": [{
            "id": "GHSA-7hp6-4w63-5g45"
        }]},
        status=200,
    )
    result = server.query_package_vulnerabilities("litellm", "PyPI", "1.91.5")
    self.assertEqual(result["vulns"][0]["id"], "GHSA-7hp6-4w63-5g45")
    sent = responses.calls[0].request
    self.assertIn(b'"version": "1.91.5"', sent.body)
    self.assertIn(b'"ecosystem": "PyPI"', sent.body)

  @responses.activate
  def test_without_version_omits_version_key(self):
    responses.post(f"{BASE}/v1/query", json={"vulns": []}, status=200)
    server.query_package_vulnerabilities("django", "PyPI")
    self.assertNotIn(b"version", responses.calls[0].request.body)

  @responses.activate
  def test_http_error_raises(self):
    responses.post(f"{BASE}/v1/query", status=500)
    with self.assertRaises(Exception):
      server.query_package_vulnerabilities("litellm", "PyPI", "1.91.5")

  @responses.activate
  def test_page_token_passed_through(self):
    """A page_token is forwarded and next_page_token is returned."""
    responses.post(
        f"{BASE}/v1/query",
        json={
            "vulns": [],
            "next_page_token": "TOK2"
        },
        status=200,
    )
    result = server.query_package_vulnerabilities(
        "Kernel", "Linux", page_token="TOK1")
    self.assertEqual(result["next_page_token"], "TOK2")
    self.assertIn(b'"page_token": "TOK1"', responses.calls[0].request.body)

  @responses.activate
  def test_page_token_omitted_when_none(self):
    """No page_token key is sent when the argument is omitted."""
    responses.post(f"{BASE}/v1/query", json={"vulns": []}, status=200)
    server.query_package_vulnerabilities("django", "PyPI")
    self.assertNotIn(b"page_token", responses.calls[0].request.body)


class QueryByCommitTest(unittest.TestCase):
  """Tests for query_by_commit."""

  @responses.activate
  def test_sends_commit(self):
    responses.post(f"{BASE}/v1/query", json={"vulns": []}, status=200)
    server.query_by_commit("6879efc2c1596d11a6a6")
    self.assertIn(b'"commit": "6879efc2c1596d11a6a6"',
                  responses.calls[0].request.body)


class QueryBatchTest(unittest.TestCase):
  """Tests for query_batch."""

  @responses.activate
  def test_wraps_queries(self):
    """A batch request wraps the queries under the "queries" key."""
    responses.post(
        f"{BASE}/v1/querybatch",
        json={"results": [{
            "vulns": []
        }, {
            "vulns": []
        }]},
        status=200,
    )
    queries = [
        {
            "package": {
                "name": "litellm",
                "ecosystem": "PyPI"
            },
            "version": "1.91.5"
        },
        {
            "commit": "abc123"
        },
    ]
    result = server.query_batch(queries)
    self.assertEqual(len(result["results"]), 2)
    self.assertIn(b'"queries"', responses.calls[0].request.body)


class GetVulnerabilityTest(unittest.TestCase):
  """Tests for get_vulnerability."""

  @responses.activate
  def test_valid_id(self):
    """A syntactically valid id is fetched from /v1/vulns/{id}."""
    vuln_id = "GHSA-7hp6-4w63-5g45"
    responses.get(
        f"{BASE}/v1/vulns/{vuln_id}",
        json={
            "id": vuln_id,
            "summary": "priv-esc"
        },
        status=200,
    )
    result = server.get_vulnerability(vuln_id)
    self.assertEqual(result["id"], vuln_id)

  @responses.activate
  def test_empty_result(self):
    """A package with no known vulns yields an empty response."""
    vuln_id = "GHSA-0000-0000-0000"
    responses.get(f"{BASE}/v1/vulns/{vuln_id}", json={}, status=200)
    self.assertEqual(server.get_vulnerability(vuln_id), {})

  @responses.activate
  def test_not_found_raises_readable_error(self):
    """A 404 surfaces the status and URL, not a bare stack trace."""
    vuln_id = "GHSA-dead-beef-0000"
    responses.get(f"{BASE}/v1/vulns/{vuln_id}", body="Not Found", status=404)
    with self.assertRaises(Exception) as ctx:
      server.get_vulnerability(vuln_id)
    self.assertIn("404", str(ctx.exception))

  def test_rejects_invalid_id(self):
    # No network call should be attempted for an id that could escape the path.
    for bad in ["../secrets", "foo/bar", "", "a..b", "x y", "a?b=c"]:
      with self.assertRaises(ValueError):
        server.get_vulnerability(bad)

  def test_accepts_known_prefixes(self):
    for good in [
        "GHSA-7hp6-4w63-5g45", "CVE-2026-114612", "PYSEC-2026-4322",
        "OSV-2021-1234", "GO-2022-0001", "RUSTSEC-2021-0001"
    ]:
      self.assertRegex(good, server.OSV_ID_RE)


if __name__ == "__main__":
  unittest.main()
