---
layout: page
title: POST /v1/querybatch
permalink: /post-v1-querybatch/
parent: API
nav_order: 3
---
# POST /v1/querybatch
Query for multiple packages (by either package and version or git commit hash) at once. Returns vulnerability ids and modified field only. The response ordering will be guaranteed to match the input.

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

[Instructions are available](#pagination) for handling pagination for querybatch requests. 

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
      },
      "page_token": "string",
    }, 
    {
      "commit": "string",
      "version": "string",
      "package": {
        "name": "string",
        "ecosystem": "string",
        "purl": "string"
      },
      "page_token": "string",
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

## Sample 200 response 
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

## Pagination

Pagination for the querybatch API works similarly to the `v1/query` endpoint. However, a querybatch request may return results with a `next_page_token` for only a few of the total queries. In this situation, you will need to run additional requests  for those specific queries to see the remaining results.

For the `v1/querybatch` endpoint pagination will occur when at least one of the following conditions are met:
- An individual query within the queryset returns more than 1,000 vulnerabilities
- The entire queryset returns more than 3,000 vulnerabilities total

These numbers can vary slightly because of threading and the page size may change in the future. 

A queryset response with paginated results will be in this form:

```json
{
  "results": [
    {
      "vulns": [
        ...
      ],
      "next_page_token": "token for query 1"
    },
    {
      "vulns": [
        ...
      ],
      "next_page_token": "token for query 2"
    },
    {
      "vulns": [
        ...
      ],
    },
    ...
  ]
}
```
Notice that each result has a distinct `next_page_token` and that the third result does not include a `next_page_token`. This indicates that all of the vulnerabilities for the third query have been returned. 

To get the next page of results, your next request should specify `page_token` only for the queries that returned `next_page_token`. 

```bash
cat <<EOF | curl -d @- "https://api.osv.dev/v1/querybatch"
{
  "queries": [
    {
      "package": {
        ...
      },
      "version": ..., 
      "page_token": next_page_token from query 1,
    },
    {
      "package": {
        ...
      },
      "version": ...,
      "page_token": next_page_token from query 2,
    },
  ]
}
EOF
```
