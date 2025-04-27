---
layout: page
title: Contributing Data from REST API
permalink: /contributing/data/rest-api/
nav_order: 3
parent: Contributing Data
---
# Contributing Data from REST API

Contributing data can be supplied either through a public Git repository, a public GCS bucket or to REST API endpoints. The below guidelines are for contributing data through REST API endpoints.

To contribute, we will need to know the following information:

### 1. A url pointing to a REST Endpoint containing at least all of the vulnerabilities' IDs and date modified:

**For example:** ``https://osv.dev/advisories/all.json``
```json
[{
 "id": "OSV-CVE-2020-1111",
 "modified": "2023-12-04T10:12:08.00Z",
},{
 "id": "OSV-CVE-2020-1112",
 "modified": "2023-12-04T10:16:25.00Z"
}]
```
The endpoint may contain more information, but at a minimum it must contain the ID and modified date of each vulnerability.

### 2. The base url of the endpoints: 
This is the base url for which the full, individual vulnerability endpoints will be appended to.

**For example:** ``https://osv.dev/advisories/``

Full vulnerability information in the osv format should be posted at the endpoint that matches their ID after the base url:  ``https://{base_url}/{id}.json``

**For example:** ``https://osv.dev/advisories/OSV-CVE-2020-1111.json``

### 3. The extension used for the individual vulnerability endpoints:
The ``.json`` extension is preferred, but discuss in your issue if you need to use a different extension.


Example source.yaml addition:
```yaml
- name: 'curl'
  versions_from_repo: False
  rest_api_url: 'https://curl.se/docs/vuln.json' # URL pointing to a REST endpoint containing at least all of the vulnerabilities' IDs and date modified
  type: 2 # 0: GIT, 1: GCS, 2: REST
  ignore_patterns: ['^(?!CURL-).*$']  # NOTE: Not currently supported for REST sources
  directory_path: 'docs' # Vulnerability data not under this path is ignored by the importer
  detect_cherrypicks: False # Whether to detect cherrypicks or not (slow for large repos)
  extension: '.json' # Extension for vulnerability data
  db_prefix: ['CURL-'] # DB prefix, as reserved in ossf. https://ossf.github.io/osv-schema/#id-modified-fields
  ignore_git: False # If true, don't analyze any Git ranges.
  human_link: 'https://curl.se/docs/{{ BUG_ID | replace("CURL-", "") }}.html'  # The human readable link
  link: 'https://curl.se/docs/' # The base link
  editable: False # Whether this repository is editable.
  strict_validation: False # Apply strict validation (JSON Schema + linter checks) to this source.

```


### Open an issue [here](https://github.com/google/osv.dev/issues).
