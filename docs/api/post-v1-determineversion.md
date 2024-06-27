---
layout: page
title: POST /v1experimental/ determineversion
permalink: /post-v1-determineversion/
parent: API
nav_order: 5
---
# POST /v1experimental/determineversion
Experimental
{: .label }

Given the source code hashes of C/C++ libraries, this endpoint attempts to find the closest upstream library and version.

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

This API endpoint is still considered experimental. We would value any and all feedback. If you give this a try, please consider [opening an issue](https://github.com/google/osv.dev/issues/new) and letting us know about any pain points or highlights.

## Purpose
The purpose of the endpoint is to help determine the package and version of a given C/C++ library. This is not as straightforward of a process compared to other ecosystems, because there is not a centralized package manager for C/C++. This API endpoint helps bridge that gap. Once you have the likely version, you can use [POST v1/query](post-v1-query.md) or [POST v1/querybatch](post-v1-querybatch.md) to search for vulnerabilities.

## Available libraries
The list of libraries that can currently be identified are the C/C++ projects integrated into the [OSS-Fuzz](https://google.github.io/oss-fuzz/) project.
This means that not all C/C++ packages are represented in our database. We're actively working on increasing this coverage, and combining this effort with [building a comprehensive database](https://github.com/google/osv.dev/issues/783) of vulnerabilities for C/C++.

To confirm if the package you are interested in can be versioned by the determineversion API, please check the following resources for your package:

1. All available package information can be found [here](https://storage.googleapis.com/osv-indexer-configs).
2. You can look up your specific package using a url in the form <!-- markdown-link-check-disable --> `https://storage.googleapis.com/osv-indexer-configs/generated/{your-package}.yaml` <!-- markdown-link-check-enable--> For example, if you are interested in the library `protobuf`, you can find information for it at [`https://storage.googleapis.com/osv-indexer-configs/generated/protobuf.yaml`](https://storage.googleapis.com/osv-indexer-configs/generated/protobuf.yaml).
3. You can use [gsutil](https://cloud.google.com/storage/docs/gsutil) to copy everything: `gsutil -m cp -r gs://osv-indexer-configs/ .`

## Try the API with our tool

We recommend trying the API endpoint with our [indexer-api-caller](https://github.com/google/osv.dev/tree/master/tools/indexer-api-caller) tool. The index-api-caller will gather all of the data (file paths and MD5 hashes) that you need, make the API call for you, and return the response.

### Steps to use the indexer-api-caller

1. Have a local copy of this repostiory.
2. Navigate to `/osv.dev/tools/indexer-api-caller`
3. Run the tool with the following commands:
  - For a single library: `go run . -lib path/to/library`
  - For a directory with multiple libraries as top level subdirectories: `go run . -dir /path/to/libs/dir`
4. Evaluate the response


### Interpreting the API response

The API will return a number of possible versions for your package, ranked by how well the version matched your local copy. Depending on the needs of your project and how close your matches were, you may want to search for vulnerabilities for a few of the most likely versions. If you are searching for multiple versions, the [/v1/querybatch endpoint](post-v1-querybatch.md) is a good choice.


## Use the API manually

If you want to use the API manually, or build your own tool to use the endpoint, the following information will help you do so.

### Parameters

|---
| Parameter               | Type   | Description                                                                       |
| ----------------------- | ------ | --------------------------------------------------------------------------------- |
| `name`                  | string | Optional name to help hint the package search.                                    |
| `file_hashes`           | array  | An array of MD5 hashes of each relevant file in the library to identify.          |
| `file_hashes.hash`      | string | the MD5 hash bytes encoded in base64.                                             |
| `file_hashes.file_path` | string | the path to the file that's hashed, relative to the root directory of the library |

Case Sensitivity: API requests are case-sensitive. Please ensure that you use the correct case for parameter names and values. For example, use 'stdlib' instead of 'Stdlib'.

### Manual API calls
After locating the library directory, walk through the directory, saving the MD5 hash of every file with the following extensions:

- `.c`
- `.cc`
- `.h`
- `.hh`
- `.cpp`
- `.hpp`

And pass each file hash to the endpoint following the format below:

### Payload
```json
{
  "name": "string",
  "file_hashes": [
    {
      "hash": "base64 string of MD5 hash bytes",
      "file_path": "string",
    }
  ]
}
```

### Response
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

### Sample 200 response
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