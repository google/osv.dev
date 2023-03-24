---
layout: page
title: POST /v1/querybatch
permalink: /post-v1-querybatch/
parent: API
nav_order: 3
---

## POST /v1/querybatch

### Request samples

#### Payload
```json
{
  "queries": [
    {
      "commit": "string",
      "version": "string",
      "package": {
        "name": "string",
        "ecosystem": "string",
        "purl": "string"
      }
    }
  ]
}
```

#### Curl
```bash
cat <<EOF | curl -d @- "https://api.osv.dev/v1/querybatch"
{
  "queries": [
    {
      "package": {
        "purl": "pkg:pypi/antlr4-python3-runtime@4.7.2"
      }
    },
    {
      "commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"
    },
    {
      "package": {
        "ecosystem": "PyPI",
        "name": "jinja2"
      },
      "version": "2.4.1"
    }
  ]
}
EOF
```

### Response samples

#### 200
```json
{
  "results": [
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
                    null
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