---
layout: page
title: POST /v1experimental/ubuntu/binary-to-source
permalink: /post-v1-ubuntu-binary-to-source/
parent: API
nav_order: 6
---
# POST /v1experimental/ubuntu/binary-to-source
Experimental
{: .label }

Map Ubuntu binary package names to their corresponding source package names.

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Experimental endpoint

This API endpoint is still considered experimental. We would value any and all
feedback. If you give this a try, please consider [opening an
issue](https://github.com/google/osv.dev/issues/new) and letting us know about
any pain points or highlights.

## Purpose

Ubuntu vulnerability advisories in OSV are indexed by source package name rather
than binary package name. This endpoint resolves one or more Ubuntu binary
package names (up to 1000 per request) to the source package names that build
them, allowing callers such as scanners to query OSV using the resulting source
package names.

## Parameters

|---
| Parameter      | Type  | Description                                                                   |
| -------------- | ----- | ----------------------------------------------------------------------------- |
| `binary_names` | array | A non-empty array of Ubuntu binary package names (maximum 1000 per request). |

## Payload

```json
{
  "binary_names": [
    "string"
  ]
}
```

## Request sample

```bash
cat <<EOF | curl -d @- "https://api.osv.dev/v1experimental/ubuntu/binary-to-source"
{
  "binary_names": [
    "libcurl4",
    "libglib2.0-0"
  ]
}
EOF
```

## Example 200 response

The response `results` array is guaranteed to match the ordering of the input
`binary_names` (with an empty object `{}` for binary package names that have no
known source package mappings):

```json
{
  "results": [
    {
      "source_names": [
        "curl"
      ]
    },
    {
      "source_names": [
        "glib2.0"
      ]
    }
  ]
}
```
