---
layout: page
title: Contributing Data from REST API
permalink: /rest-api-contribution/
nav_order: 2
parent: Contributing
---
# Contributing Data from REST API

Contributing data can be supplied either through a public Git repository, a public GCS bucket or to REST API endpoints. The below guidelines are for contributing data through REST API endpoints.

To contribute, we will need to know the following information:

### 1. A url pointing to a REST Endpoint containing at least all of the vulnerabilities' IDs and date modified:

**For example:** ``https://osv.dev/advisories/all.json``
```json
{
 "id": "OSV-CVE-2020-1111",
 "modified": "2023-12-04T10:12:08.00Z",
},{
 "id": "OSV-CVE-2020-1112",
 "modified": "2023-12-04T10:16:25.00Z"
}
```
The endpoint may contain more information, but at a minimum it must contain the ID and modified date of each vulnerability.

### 2. The base url of the endpoints: 
This is the base url for which the full, individual vulnerability endpoints will be appended to.

**For example:** ``https://osv.dev/advisories/``

Full vulnerability information in the osv format should be posted at the endpoint that matches their ID after the base url:  ``https://{base_url}/{id}.json``

**For example:** ``https://osv.dev/advisories/OSV-CVE-2020-1111.json``

### 3. The extension used for the individual vulnerability endpoints:
The ``.json`` extension is preferred, but discuss in your issue if you need to use a different extension.


### Open an issue [here](https://github.com/google/osv.dev/issues).
