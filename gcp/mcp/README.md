# OSV MCP Server

A standalone Model Context Protocol (MCP) server that provides a translation layer to the OSV HTTP API.

## Overview

This MCP server acts as a bridge between MCP clients (like Claude Desktop, Cursor, or other AI assistants) and the OSV REST API.

### Architecture

```
┌──────────────┐      ┌────────────────────┐      ┌──────────────┐
│              │      │   OSV MCP Server   │      │              │
│  MCP Client  │─────▶│  (Translation      │─────▶│  HTTP API    │
│  (AI Agent)  │ MCP  │   Layer)           │ HTTP │ (OSV REST)   │
│              │      │                    │      │              │
└──────────────┘      └────────────────────┘      └──────────────┘
  stdio or SSE            server.py             api.osv.dev
```

## Features

### MCP Tools

The server exposes 4 MCP tools that map to OSV HTTP API endpoints:

1. **`get_vulnerability_by_id`** - Get vulnerability details by OSV ID
2. **`query_affected`** - Query vulnerabilities for packages/versions/commits
3. **`query_affected_batch`** - Batch query multiple packages (up to 1000)
4. **`determine_version`** - Identify project versions from file hashes

## Installation

### Prerequisites

- Python 3.13+
- Poetry (for dependency management)
- Internet connection to access OSV HTTP API (default: `https://api.osv.dev`)

### Setup

```bash
# Navigate to the mcp directory
cd gcp/mcp

# Install dependencies with Poetry
poetry install
```

## Usage

### Running the Server

#### stdio Mode (for MCP clients)

```bash
# Run with stdio transport (default)
poetry run python server.py

# Or with custom API endpoint
poetry run python server.py --api-endpoint=https://api.osv.dev
```

#### SSE Mode (for HTTP clients)

```bash
# Run with SSE transport
poetry run python server.py --transport=sse --mcp-port=8001

# With custom configuration
poetry run python server.py \
    --transport=sse \
    --mcp-host=0.0.0.0 \
    --mcp-port=8001 \
    --api-endpoint=https://api.osv.dev \
    --log-level=DEBUG
```

### Command Line Options

```
--api-endpoint     OSV API endpoint URL (default: https://api.osv.dev)
--mcp-host         MCP server host for SSE (default: 127.0.0.1)
--mcp-port         MCP server port for SSE (default: 8001)
--transport        Transport protocol: stdio or sse (default: stdio)
--log-level        Logging level: DEBUG, INFO, WARNING, ERROR (default: INFO)
```
## MCP Clients

Theoretically, any MCP client should work with osv-mcp.  Three examples are given below.

## Example 1: Claude Desktop
To set up Claude Desktop as a OSV MCP client, go to `Claude` -> `Settings` -> `Developer` -> `Edit Config` -> `claude_desktop_config.json` and add the following:

```json
{
  "mcpServers": {
    "osv": {
      "command": "/ABSOLUTE_PATH_TO/osv.dev/gcp/mcp/start_server.sh"
    }
  }
}
```

## Example 2: Cline
To use OSV MCP server with [Cline](https://cline.bot), this requires manually running the MCP server as well. First run the following command:

```
/ABSOLUTE_PATH_TO/osv.dev/gcp/mcp
poetry install
poetry run python server.py --transport sse --mcp-host 127.0.0.1 --mcp-port 8001
```
