---
layout: page
title: POST /v1/query
permalink: /post-v1-query/
parent: API
nav_order: 2
---
# POST /v1/query

Lists vulnerabilities for given package and version. May also be queried by commit hash. 

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Parameters
  
|---
| Parameter | Type | Description |
| --- | --- | --- |
| commit | string | The commit hash to query for. If specified, `version` should not be set. |
| version | string | The version string to query for. A fuzzy match is done against upstream versions. If specified, `commit` should not be set. |
| package | object | The package to query against. When a `commit` hash is given, this is optional. |

Package Objects have the following attributes:

|---
| Attribute | Type | Required or Optional? | Description |
| --- | --- | --- | --- |
| name | string | Required | Name of the package. Should match the name used in the package ecosystem (e.g. the npm package name). For C/C++ projects integrated in OSS-Fuzz, this is the name used for the integration.|
| ecosystem | string | Required | The ecosystem for this package. For the complete list of valid ecosystem names, see [here](https://ossf.github.io/osv-schema/#affectedpackage-field). |
| purl | string | Optional | The package URL for this package. |

## Payload
```json
{
  "commit": "string",
  "version": "string",
  "package": {
    "name": "string",
    "ecosystem": "string",
    "purl": "string"
  }
}
```

## Request samples

```bash
curl -d \
  '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
  "https://api.osv.dev/v1/query"

curl -d \
  '{"package": {"name": "mruby"}, "version": "2.1.2rc"}' \
  "https://api.osv.dev/v1/query"
  ```

## Response samples

### Sample 200 response
```json
{
  "vulns": [
    {
      "schemaVersion": "string",
      "id": "string",
      "published": "2019-08-24T14:15:22Z",
      "modified": "2019-08-24T14:15:22Z",
      "withdrawn": "2019-08-24T14:15:22Z",
      "aliases": [
        "string"
      ],
      "related": [
        "string"
      ],
      "summary": "string",
      "details": "string",
      "affected": [
        {
          "package": {
            "name": "string",
            "ecosystem": "string",
            "purl": "string"
          },
          "ranges": [
            {
              "type": "UNSPECIFIED",
              "repo": "string",
              "events": [
                {
                  "introduced": "string",
                  "fixed": "string",
                  "limit": "string"
                }
              ]
            }
          ],
          "versions": [
            "string"
          ],
          "ecosystemSpecific": {},
          "databaseSpecific": {}
        }
      ],
      "references": [
        {
          "type": "NONE",
          "url": "string"
        }
      ],
      "severity": [
        {
          "type": "UNSPECIFIED",
          "score": "string"
        }
      ],
      "credits": [
        {
          "name": "string",
          "contact": [
            "string"
          ]
        }
      ],
      "database_specific": {}
    }
  ]
}
```

### Default response
```json
{
  "code": 0,
  "message": "string",
  "details": [
    {
      "typeUrl": "string",
      "value": "string"
    }
  ]
}
```