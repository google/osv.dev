---
layout: page
title: POST /v1/query
permalink: /post-v1-query/
parent: API
nav_order: 2
---
# POST /v1/query

Lists vulnerabilities for given package and version. May also be queried by commit hash.

To query multiple packages at once, see further information [here](post-v1-querybatch.md). 

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
| Parameter    | Type   | Description                                                                                                                                                                                 |
| ------------ | ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `commit`     | string | The commit hash to query for. If specified, `version` should not be set.                                                                                                                    |
| `version`    | string | The version string to query for. A fuzzy match is done against upstream versions. If specified, `commit` should not be set.                                                                 |
| `package`    | object | The package to query against. When a `commit` hash is given, this is optional.                                                                                                              |
| `page_token` | string | If your previous query fetched a large number of results, the response will be paginated. This is an optional field. Please see the [pagination section](#pagination) for more information. |

Package Objects can be described by package name AND ecosystem OR by the package URL. 

|---
| Attribute   | Type   | Description                                                                                                                                                                                                                                                                                     |
| ----------- | ------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`      | string | Name of the package. Should match the name used in the package ecosystem (e.g. the npm package name). For C/C++ projects integrated in OSS-Fuzz, this is the name used for the integration. If using `name` to specify the package, `ecosystem` must also be used and `purl` should not be set. |
| `ecosystem` | string | The ecosystem for this package. For the complete list of valid ecosystem names, see [here](https://ossf.github.io/osv-schema/#affectedpackage-field). Must be included if identifying the package by `name`. If specifying by `name` and `ecosystem`, `purl` should not be set.                 |
| `purl`      | string | The package URL for this package. If `purl` is used to specify the package, `name` and `ecosystem` should not be set.                                                                                                                                                                           |

Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use 'PyPI' instead of 'pypi'.

### Queries for Git records
You can also query for git tags via this API. To do so, set the `ecosystem` to `GIT`, enter the full URL of the repository to the `name` field, and the tag into the `version` field. See below for an example.

## Payload
```json
{
  "commit": "string",
  "version": "string",
  "package": {
    "name": "string",
    "ecosystem": "string",
    "purl": "string"
  },
  "page_token": "string"
}
```

## Request samples

```bash
# Commit query
curl -d \
  '{"commit": "6879efc2c1596d11a6a6ad296f80063b558d5e0f"}' \
  "https://api.osv.dev/v1/query"

# Package and version query
curl -d \
  '{"package": {"name": "nokogiri", "ecosystem": "RubyGems"}, "version": "1.18.2"}' \
  "https://api.osv.dev/v1/query"

# Git query by tag
curl -d \
  '{"package": {"name": "https://github.com/curl/curl.git", "ecosystem": "GIT"}, "version": "8.5.0"}' \
  "https://api.osv.dev/v1/query"
```

## Sample 200 response
```json
{
  "vulns": [
    {
      "id": "OSV-2020-744",
      "summary": "Heap-double-free in mrb_default_allocf",
      "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801\n\n```\nCrash type: Heap-double-free\nCrash state:\nmrb_default_allocf\nmrb_free\nobj_free\n```\n",
      "modified": "2022-04-13T03:04:39.780694Z",
      "published": "2020-07-04T00:00:01.948828Z",
      "references": [
        {
          "type": "REPORT",
          "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=23801"
        }
      ],
      "affected": [
        {
          "package": {
            "name": "mruby",
            "ecosystem": "OSS-Fuzz",
            "purl": "pkg:generic/mruby"
          },
          "ranges": [
            {
              "type": "GIT",
              "repo": "https://github.com/mruby/mruby",
              "events": [
                {
                  "introduced": "9cdf439db52b66447b4e37c61179d54fad6c8f33"
                },
                {
                  "fixed": "97319697c8f9f6ff27b32589947e1918e3015503"
                }
              ]
            }
          ],
          "versions": [
            "2.1.2",
            "2.1.2-rc",
            "2.1.2-rc2"
          ],
          "ecosystem_specific": {
            "severity": "HIGH"
          },
          "database_specific": {
            "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/mruby/OSV-2020-744.yaml"
          }
        }
      ],
      "schema_version": "1.4.0"
    }
  ]
}

```

## Pagination

The OSV.dev API uses pagination for queries that return a large number of vulnerabilities. When pagination is used, the `next_page_token` is given in the response, indicating that there are more results to return. You will need to run additional queries using the `page_token` to see the remaining results, repeating queries until the `next_page_token` is no longer included in the response. 

For the `v1/query` endpoint pagination will occur when there more than 1,000 vulnerabilities in the response, or when the query has exceeded 20 seconds. The page size can vary slightly because of threading and may change in the future.

A response indicating pagination will be in this form:
```json
{
  "vulns": [
    ...
  ],
  "next_page_token": "a base64 string here"
}
```

To get the next page of results, your next request must include page_token:
```bash

curl -d \
  '{"package": {...}, "version": ..., "page_token": next_page_token from response}' \
  "https://api.osv.dev/v1/query"

```

{: .note }
The API has a response size limit of 32MiB when using HTTP/1.1. There is **no limit** when using HTTP/2. We recommend using HTTP/2 for queries that may result in large responses.

{: .note }
In rare cases, the response might contain **only** the `next_page_token`. In those cases, there might be more data that can be retrieved, but were not found within the time limit, please keep querying with the `next_page_token` until either results are returned, or no more page tokens are returned. 