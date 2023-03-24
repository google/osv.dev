---
layout: page
title: POST /v1/query
permalink: /post-v1-query/
parent: API
nav_order: 2
---

## POST /v1/query

### Request samples

#### Payload
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

#### Curl
```bash
curl -d \
  '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
  "https://api.osv.dev/v1/query"

curl -d \
  '{"package": {"name": "mruby"}, "version": "2.1.2rc"}' \
  "https://api.osv.dev/v1/query"
  ```

### Response samples

#### 200
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