# OSV MCP server

## About

A [Model Context Protocol](https://modelcontextprotocol.io) (MCP) server that
exposes the [OSV.dev](https://osv.dev) vulnerability database as tools for AI
agents. It is a thin wrapper over the stable public OSV REST API
(`https://api.osv.dev`) — an agent can ask "is `litellm` 1.91.5 vulnerable?" and
get machine-readable advisories back, without the agent needing to know the HTTP
contract.

The server is self-contained: it only depends on the `mcp` SDK and `requests`,
and does not use the `osv` Python library or any GCP services.

## Tools

| Tool | OSV endpoint | Description |
|---|---|---|
| `query_package_vulnerabilities(package_name, ecosystem, version=None, page_token=None)` | `POST /v1/query` | Vulnerabilities for a package; all known vulns if `version` is omitted. |
| `query_by_commit(commit, page_token=None)` | `POST /v1/query` | Vulnerabilities affecting a source commit. |
| `query_batch(queries)` | `POST /v1/querybatch` | Many package/commit queries in one request (max 1000). |
| `get_vulnerability(vuln_id)` | `GET /v1/vulns/{id}` | Full OSV record for a single advisory ID. |

Valid `ecosystem` values are listed in the
[OSV schema](https://ossf.github.io/osv-schema/#affectedpackage-field)
(`PyPI`, `npm`, `Go`, `Maven`, `crates.io`, ...).

The two single-query tools are paginated: when a response includes a
`next_page_token`, pass it back as `page_token` to fetch the next page.

## Install

```shell
cd tools/osv-mcp
poetry install
```

## Run

Over stdio (the default MCP transport):

```shell
poetry run osv-mcp
# or
poetry run python -m osv_mcp.server
```

Set `OSV_API_BASE_URL` to target a non-production endpoint (e.g. a local API
dev server or staging):

```shell
OSV_API_BASE_URL=http://localhost:8080 poetry run osv-mcp
```

`OSV_API_BASE_URL` is operator configuration — set it only to a trusted
endpoint, since every tool call is sent to that host.

## Using it from an MCP client

Register the server with any MCP client. For Claude Code:

```shell
claude mcp add osv -- poetry --directory /path/to/osv.dev/tools/osv-mcp run osv-mcp
```

Or add it directly to a client config (`.mcp.json` / `claude_desktop_config.json`):

```json
{
  "mcpServers": {
    "osv": {
      "command": "poetry",
      "args": ["--directory", "/path/to/osv.dev/tools/osv-mcp", "run", "osv-mcp"]
    }
  }
}
```

## Tests

HTTP is mocked, so no network access or GCP credentials are required:

```shell
poetry run python -m unittest discover -p '*_test.py'
# or
./run_tests.sh
```
