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

Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use 'GHSA' instead of 'ghsa'.

## Request sample

```bash
curl "https://api.osv.dev/v1/vulns/OSV-2020-111"
```

## Sample 200 response
```json
{
  "id": "OSV-2020-111",
  "summary": "Heap-use-after-free in int std::__1::__cxx_atomic_fetch_sub<int>",
  "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604\n\n```\nCrash type: Heap-use-after-free WRITE 4\nCrash state:\nint std::__1::__cxx_atomic_fetch_sub<int>\nstd::__1::__atomic_base<int, true>::operator--\nObject::free\n```\n",
  "modified": "2022-04-13T03:04:37.331327Z",
  "published": "2020-06-24T01:51:14.570467Z",
  "references": [
    {
      "type": "REPORT",
      "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=21604"
    }
  ],
  "affected": [
    {
      "package": {
        "name": "poppler",
        "ecosystem": "OSS-Fuzz",
        "purl": "pkg:generic/poppler"
      },
      "ranges": [
        {
          "type": "GIT",
          "repo": "https://anongit.freedesktop.org/git/poppler/poppler.git",
          "events": [
            {
              "introduced": "e4badf4d745b8e8f9a0a25b6c3cc97fbadbbb499"
            },
            {
              "fixed": "155f73bdd261622323491df4aebb840cde8bfee1"
            }
          ]
        }
      ],
      "ecosystem_specific": {
        "severity": "HIGH"
      },
      "database_specific": {
        "source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/poppler/OSV-2020-111.yaml"
      }
    }
  ],
  "schema_version": "1.4.0"
}
```