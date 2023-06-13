---
layout: page
title: Experimental determineversion
permalink: /post-v1-determineversion/
parent: API
nav_order: 5
---
# POST /v1experimental/determineversion
Experimental
{: .label }

Given the source code of C/C++ libraries, this endpoint attempts to find the closest library and version.

The purpose of the endpoint is to help determine the version of a given C/C++ library. It is difficult to know the correct version of C/C++ projects because there is not a centralized package manager within the ecosystem. This API endpoint helps bridge that gap. Once you have the likely version, you can use [POST v1/query](post-v1-query.md) or [POST v1/queryset](post-v1-queryset.md) to search for vulnerabilities. 

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

As this is an experimental feature, we would love to hear about your experience using it. If you give this a try, please consider [opening an issue](https://github.com/google/osv.dev/issues/new) and letting us know about any pain points or highlights. 

## Usage

After locating the library directory, walk through the directory, saving the MD5 hash of every file with the following extensions:

- `.c`   
- `.cc`  
- `.h`   
- `.hh`  
- `.cpp` 
- `.hpp` 

And pass each file hash to the endpoint following the format below:

## Parameters

|---
| Parameter               | Type   | Description                                                                       |
| ----------------------- | ------ | --------------------------------------------------------------------------------- |
| `name`                  | string | Optional name to help hint the package search.                                    |
| `file_hashes`           | array  | An array of file hashes of each relevant file in the library to identify.         |
| `file_hashes.hash`      | string | the MD5 hash bytes encoded in base64.                                             |
| `file_hashes.file_path` | string | the path to the file that's hashed, relative to the root directory of the library |

## Payload
```json
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
```json
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
```json
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