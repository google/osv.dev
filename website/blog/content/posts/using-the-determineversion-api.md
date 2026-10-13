---
title: "Using the determineversion API to find C/C++ vulnerabilities"
date: 2023-07-20T11:00:00+10:00
draft: false
author: OSV Team
---

With the increasing incidence of software supply chain attacks, it is more important than ever for developers to understand the known vulnerabilities in their open source dependencies, regardless of the ecosystem of origin. The determineversion API is OSV's newest tool that will help C/C++ developers match their dependencies to known vulnerabilities. 

Within the C/C++ ecosystem it is difficult to match dependencies to vulnerabilities for a few reasons:

- C/C++ does not have a centralized package manager like npm or pyPI
- Software projects typically pull in C/C++ by submodules or vendoring
- Source code identifiers (e.g. git hashes) are the best way to identify libraries, but vulnerabilities are typically associated to versions, not git hashes

OSV has had C/C++ vulnerability data from OSS-Fuzz keyed on git hashes from day 1. However, a remaining challenge for C/C++ users is being able to accurately identify the closest upstream git hash of their C/C++ dependencies in order to make use of this vulnerability data. The OSV team is committed to bridging the gap between what C/C++ users need and the constraints of the ecosystem and the determineversion API is part of our plan for comprehensive C/C++ support. 
<!--more-->

## What is the determineversion API?
The [determineversion API](https://google.github.io/osv.dev/post-v1-determineversion/) is a new, experimental API endpoint for OSV’s API. The goal of the determineversion API is to help users determine the likely version of their vendored C/C++ dependencies. Once dependency versions are known, our other API endpoints can return reliable vulnerability information. 

## What projects can use the determineversion API?
The set of C/C++ repositories currently supported by the determineversion API are the ones being fuzzed by [OSS-Fuzz](https://github.com/google/oss-fuzz). This is because OSV currently only contains commit-level vulnerability information for C/C++ projects via OSS-Fuzz. If a project has been fuzzed by OSS-Fuzz, you’ll be able to use the tool, but you should understand that there may be additional vulnerabilities in your dependencies that weren’t found by or reported through OSS-Fuzz. You can check a project against the API's current limitations by following the steps in our [documentation](https://google.github.io/osv.dev/post-v1-determineversion/#available-libraries). 

The OSV team is also working on expanding C/C++ coverage by including commit-level details for vulnerabilities from CVEs in the National Vulnerability Database(NVD). Once this is complete, our vulnerability matching for C/C++ will be comprehensive. 

## Let's try the determineversion API
To try the determineversion API, you will first need the following:

- A local copy of the [osv.dev repository](https://github.com/google/osv.dev). This includes a tool that will simplify the use of the API.
- A local copy of the C/C++ project or projects for which you want to determine the version(s). This local copy can be vendored, submoduled, or you can clone a copy of our example project, [libxml2](https://github.com/GNOME/libxml2).

You can follow along with this post, or consult our [documentation](https://google.github.io/osv.dev/post-v1-determineversion/) for information on how to use the API. 

For this example, we are going to use the library [libxml2](https://github.com/GNOME/libxml2). First we are going to estimate which version of libxml2 is on my machine and then determine whether it has any known vulnerabilities.

To determine the version of libxml2 and find the associated vulnerabilities:

### Step 1: Navigate to the indexer-api-caller tool
Navigate to the indexer-api-caller folder in your local copy of the osv.dev repository. It is located in `osv.dev/tools/indexer-api-caller/`

### Step 2: Run the indexer-api-caller tool to access the determineversion API
While in that folder, run the command `go run . -lib /path/to/library` where `path/to/library` is the path to your copy of libxml2. On my machine, the command looks like this: `go run . -lib ../../../libxml2`. 

### Step 3: Inspect the response and choose the likely version
The indexer-api-caller returns the determineversion API response, which we are now going to inspect. In order to save space in the post, I have cut the response to the top 4 potential libxml2 versions (out of 10 in the response). 
```json
{
	"matches": [
		{
		"score": 0.7180851063829787,
		"repo_info": {
			"type": "GIT",
			"address": "https://gitlab.gnome.org/GNOME/libxml2.git",
			"tag": "v2.11.3",
			"version": "2.11.3",
			"commit": "787ae0390a3b90a76c2c54d6a18d7f1abe888c64"
		},
		"minimum_file_matches": "113",
		"estimated_diff_files": "53"
		},
		{
		"score": 0.7180851063829787,
		"repo_info": {
			"type": "GIT",
			"address": "https://gitlab.gnome.org/GNOME/libxml2.git",
			"tag": "v2.11.4",
			"version": "2.11.4",
			"commit": "2e9f7860a9cb8be29eca90b7409ef0278d30ef10"
		},
		"minimum_file_matches": "112",
		"estimated_diff_files": "53"
		},
		{
		"score": 0.7074468085106383,
		"repo_info": {
			"type": "GIT",
			"address": "https://gitlab.gnome.org/GNOME/libxml2.git",
			"tag": "v2.11.2",
			"version": "2.11.2",
			"commit": "838bf42d54f94c8ff99b6e5022899a32875ed5d7"
		},
		"minimum_file_matches": "112",
		"estimated_diff_files": "55"
		},
		{
		"score": 0.6968085106382979,
		"repo_info": {
			"type": "GIT",
			"address": "https://gitlab.gnome.org/GNOME/libxml2.git",
			"tag": "v2.11.0",
			"version": "2.11.0",
			"commit": "f296934ade688baab79caf1c62a82149ad78accf"
		},
		"minimum_file_matches": "110",
		"estimated_diff_files": "57"
		},
	]
}
```
The best match indicates that the likely libxml2 version is `2.11.3` based on 113 matching files. The confidence scores for versions `2.11.3`, `2.11.4`, `2.11.2`, and `2.11.0` are very close but we shouldn't think of them as equally likely to be the actual version. We recommend considering the version with the highest confidence score to be the project's version. When scores are equivalent, consider the number of matching files--which is why `2.11.3` is preferred in this case over `2.11.4`. `2.11.3` has one more matching file. 

### Step 4: Query for known vulnerabilities
Now that we have the likely version, we can use the [`/v1/query` endpoint](https://google.github.io/osv.dev/post-v1-query/) to find known vulnerabilities. The request is as follows:
```bash
curl -d \
	'{"package": {"name": "libxml2"}, "version":"2.11.3"}' \
	"https://api.osv.dev/v1/query"
```
And we get a response:

```json
{
	"vulns": [
		{
		"id": "OSV-2021-777",
		"summary": "Heap-use-after-free in xmlAddNextSibling",
		"details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=34461\n\n```\nCrash type: Heap-use-after-free  READ4\nCrash state:\nxmlAddNextSibling\nxmlXIncludeCopyRange\nxmlXIncludeCopyXPointer\n```\n",
		"modified": "2023-05-19T14:06:37.864410Z",
		"published": "2021-05-20T00:00:30.166614Z",
		"references": [
			{
			"type": "REPORT",
			"url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=34461"
			}
		],
		"affected": [
			{
			"package": {
				"name": "libxml2",
				"ecosystem": "OSS-Fuzz",
				"purl": "pkg:generic/libxml2"
			},
			"ranges": [
				{
				"type": "GIT",
				"repo": "https://gitlab.gnome.org/GNOME/libxml2.git",
				"events": [
					{
					"introduced": "6c128fd58a0e4641c23a345d413672494622db1b"
					}
				]
				}
			],
			"versions": [
				"CVE-2021-3541",
				"v2.9.11",
				"v2.9.12",
				"v2.9.13",
				"v2.9.14",
				"v2.10.0",
				"v2.10.1",
				"v2.10.2",
				"v2.10.3",
				"v2.10.4",
				"v2.11.0",
				"v2.11.1",
				"v2.11.2",
				"v2.11.3",
				"v2.11.4"
			],
			"ecosystem_specific": {
				"severity": "HIGH"
			},
			"database_specific": {
				"source": "https://github.com/google/oss-fuzz-vulns/blob/main/vulns/libxml2/OSV-2021-777.yaml"
			}
			}
		],
		"schema_version": "1.4.0"
		}
	]
}
```
		
### Step 5: Consider the response
Finally, we consider the response and draw conclusions. 

To be sure we have caught any potential vulnerabilities, we could make further queries for other versions with similar scores. It is our opinion that this is generally unnecessary, but it could be done. 

In this case, even if the actual version is not `2.11.3`, we can be fairly confident that the vulnerability that we found ([OSV-2021-777](https://osv.dev/vulnerability/OSV-2021-777)) is in our local copy of libxml2. This is because there is overlap between the other likely versions of libxml2 and the versions vulnerable to OSV-2021-777.

By running our tool and making one additional API call, we now are fairly confident that my local version of libxml2 has known vulnerability OSV-2021-777.

## Try for yourself
Want to find vulnerabilities in your C/C++ packages? Try the determineversion API for yourself! (This blog covered how to scan an individual project, but it is also possible to [scan a directory](https://google.github.io/osv.dev/post-v1-determineversion/#steps-to-use-the-indexer-api-caller) with multiple libraries.) We are actively seeking feedback on the determineversion API to improve this tool and our overall support of the C/C++ ecosystem. If you have a project that you would like to scan for vulnerabilities, please follow along with this post's walkthrough and let us [know about your experience](https://github.com/google/osv.dev/issues/new).

The OSV team is building tools to help C/C++ developers find vulnerabilities in their dependencies. The determineversion API is the first step, but later this year we will introduce commit level details from CVEs in the NVD. Subscribe to our [RSS feed](https://osv.dev/blog/index.xml) to hear the latest news. 

