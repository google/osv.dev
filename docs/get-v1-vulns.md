---
layout: page
title: GET /v1/vulns/{id}
permalink: /get-v1-vulns/
parent: API
nav_order: 4
---
# GET /v1/vulns/{id}
Returns vulnerability information for a given vulnerability id. 

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

The only parameter you need for this API call is the vulnerability id, in order to construct the URL. 

`https://api.osv.dev/v1/vulns/{id}`

## Request sample

```bash
curl "https://api.osv.dev/v1/vulns/OSV-2020-111"
```

## Response samples

### Sample 200 response
```json
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
```