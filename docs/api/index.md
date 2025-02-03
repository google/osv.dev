---
layout: page
title: API
permalink: /api/
has_children: true
nav_order: 2
---
# API (1.0)

## Download the OpenAPI specification

[Download Here](https://osv.dev/docs/osv_service_v1.swagger.json){: .btn .btn-purple}

## OSV API
  
### Want a quick example?  

Please see the [quickstart](api-quickstart.md).

### How does the API work?

There are five different types of requests that can be made of the API.

1. Query vulnerabilities for a particular project at a given [commit hash or version](post-v1-query.md).
2. [Batched query vulnerabilities](post-v1-querybatch.md) for given package versions and commit hashes.
3. Return a `Vulnerability` object for a given [OSV ID](get-v1-vulns.md). 
4. Return a list of [probable versions](post-v1-determineversion.md) of a specified C/C++ project. (**Experimental**)
5. Retrieve [records failing import-time quality checks](get-v1-importfindings.md), by record source (**Experimental**)

### Is the API rate limited?  

Currently there are no limits on the API.
