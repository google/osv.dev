---
layout: page
title: POST /v1experimental/determineversion
permalink: /post-v1experimental-determineversion/
parent: API
nav_order: 2
---
# POST /v1experimental/determineversion

Given the source code of C/C++ libraries, 
this endpoint attempts to find the closest library and version.

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
| Parameter               | Type   | Description                                                                       |
| ----------------------- | ------ | --------------------------------------------------------------------------------- |
| `name`                  | string | Optional name to help hint the package search.                                    |
| `file_hashes`           | array  | An array of file hashes of each relevant file in the library to identify.         |
| `file_hashes.hash`      | string | the hash bytes encoded in base64.                                                 |
| `file_hashes.file_path` | string | the path to the file that's hashed, relative to the root directory of the library |

## Payload
```json5
{
  "name": "string",
  "file_hashes": [
    {
      "hash": "base64 string of hash bytes",
      "file_path": "string",
    }
  ]
}
```

## Response
Returns an array of potential library matches, sorted by how close the match is.
```json5
{
  "matches": [
    {
      "score": 0.5, // float between 0.0 - 1.0
      "repo_info": {
        "type": "string", // e.g. GIT
        "address": "string", // Repo Address
        "tag": "string", // Git tag
        "version": "string" // Library version
      },
      "minimum_file_matches": "string", // Number of exact hash matches
      "estimated_diff_files": "string" // Estimated number of different files
    },
  ]
}
```

## Sample 200 response
```json5
{
  "matches": [
    {
      "score": 1,
      "repo_info": {
        "type": "GIT",
        "address": "https://github.com/protocolbuffers/protobuf.git",
        "tag": "v4.22.2",
        "version": "4.22.2"
      },
      "minimum_file_matches": "617"
    },
    {
      "score": 0.97730956239870337,
      "repo_info": {
        "type": "GIT",
        "address": "https://github.com/protocolbuffers/protobuf.git",
        "tag": "v4.22.1",
        "version": "4.22.1"
      },
      "minimum_file_matches": "575",
      "estimated_diff_files": "14"
    }
  ]
}

```