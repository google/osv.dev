---
layout: page
title: via REST API
permalink: /data/new/rest-api
nav_order: 1
parent: New Data Source
---

# Contributing Data via REST API

Contributing data can be supplied either through a public Git repository, REST API endpoints, or a public GCS bucket. The below guidelines are for contributing data through REST API endpoints.

To contribute, we will need to know the following information:

### 1. A url pointing to a REST Endpoint containing at least all of the vulnerabilities' IDs and date modified:

**For example:** ``https://osv.dev/advisories/all.json``
```json
[{
 "id": "OSV-CVE-2020-1111",
 "modified": "2023-12-04T10:12:08.00Z"
},{
 "id": "OSV-CVE-2020-1112",
 "modified": "2023-12-04T10:16:25.00Z"
}]
```
The endpoint may contain more information, but at a minimum it must contain the ID and modified date of each vulnerability.

This endpoint must be configured to allow both HEAD and GET requests, with Last-Modified metadata provided to reduce unnecessary requests and traffic. 

### 2. The base url of the endpoints: 
This is the base url for which the full, individual vulnerability endpoints will be appended to.

**For example:** ``https://osv.dev/advisories/``

Full vulnerability information in the osv format should be posted at the endpoint that matches their ID after the base url:  ``https://{base_url}/{id}.json``

**For example:** ``https://osv.dev/advisories/OSV-CVE-2020-1111.json``

### 3. The extension used for the individual vulnerability endpoints:
The ``.json`` extension is preferred, but discuss in your issue if you need to use a different extension.

### 4. A URL documenting the license for the data:
Provide a link to a publicly accessible page stating the license under which the vulnerability data is published (for example, [CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/) or [CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/)).


### Open an issue [here](https://github.com/google/osv.dev/issues).
