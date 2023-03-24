---
layout: page
title: GET /v1/vulns/{id}
permalink: /get-v1-vulns/
parent: API
nav_order: 3
---

## GET /v1/vulns/{id}

### Request samples

#### Curl
```bash
curl "https://api.osv.dev/v1/vulns/OSV-2020-111"
```

### Response samples

#### 200
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

#### Default
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