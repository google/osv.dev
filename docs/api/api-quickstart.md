---
layout: page
title: API Quickstart
permalink: /quickstart/
parent: API
nav_order: 2
---
# Quickstart

Here are a couple of examples that you can run to get an idea of the API. See [here](index.md#osv-api) for further information.  

## Return a vulnerability associated with a commit hash
  
```bash
curl -d '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
    "https://api.osv.dev/v1/query"
```

## Return all vulnerabilities for a given package
  
```bash
curl -d \
          '{"version": "2.4.1", "package": {"name": "jinja2", "ecosystem": "PyPI"}}' \
          "https://api.osv.dev/v1/query"
```
