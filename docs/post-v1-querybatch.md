---
layout: page
title: POST /v1/querybatch
permalink: /post-v1-querybatch/
parent: API
nav_order: 3
---
# POST /v1/querybatch
Query for multiple packages (by either package and version or git commit hash) at once. Returns vulnerability ids and modified field only.  

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

The parameters are the same as those in found [here](post-v1-query.md#parameters), but you can make multiple queries.

## Payload
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
    }, 
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

## Request sample

```bash
cat <<EOF | curl -d @- "https://api.osv.dev/v1/querybatch"
{
  "queries": [
    {
      "package": {
        "purl": "pkg:pypi/mlflow@0.4.0"
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

## Response samples

### Sample 200 response 
```json
{
  "results":
    [
      {
        "vulns":
          [
            {
              "id":"GHSA-vqj2-4v8m-8vrq",
              "modified":"2023-03-14T05:47:39.989396Z"
            },
            {
              "id":"GHSA-wp72-7hj9-5265",
              "modified":"2023-03-24T22:28:29.389429Z"
            },
            {
              "id":"GHSA-xg73-94fp-g449",
              "modified":"2023-03-24T22:54:55.516821Z"
            },
            {
              "id":"PYSEC-2022-28",
              "modified":"2022-03-02T06:39:30.836439Z"
            }
          ]
      },
      {
        "vulns":
          [
            {
              "id":"OSV-2020-484",
              "modified":"2022-04-13T03:04:32.842142Z"
            }
          ]
      },
      {
        "vulns":
          [
            {
              "id":"GHSA-462w-v97r-4m45",
              "modified":"2023-03-10T05:23:41.874079Z"
            },
            {
              "id":"GHSA-8r7q-cvjq-x353",
              "modified":"2023-03-08T05:47:11.461578Z"
            },
            {
              "id":"GHSA-fqh9-2qgg-h84h",
              "modified":"2023-03-09T05:31:42.262435Z"
            },
            {
              "id":"GHSA-g3rq-g295-4j3m",
              "modified":"2023-03-12T05:29:26.243227Z"
            },
            {
              "id":"GHSA-hj2j-77xm-mc5v",
              "modified":"2023-03-12T05:32:53.675797Z"
            },
            {
              "id":"PYSEC-2014-8",
              "modified":"2021-07-05T00:01:22.043149Z"
            },
            {
              "id":"PYSEC-2014-82",
              "modified":"2021-08-27T03:22:05.027573Z"
            },
            {
              "id":"PYSEC-2019-217",
              "modified":"2021-11-22T04:57:52.862665Z"
            },
            {
              "id":"PYSEC-2019-220",
              "modified":"2021-11-22T04:57:52.929678Z"
            },
            {
              "id":"PYSEC-2021-66",
              "modified":"2021-03-22T16:34:00Z"
            }
          ]
        }
    ]
}
```
### Default response
```json
{
  "results":
    [
      {
        "vulns":
          [
            {
              "id": "string",
              "modified": "string"
            },
          ]
      },
    ]
}
```