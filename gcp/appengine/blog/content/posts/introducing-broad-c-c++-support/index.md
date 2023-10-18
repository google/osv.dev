---
title: "Introducing broad C/C++ vulnerability management support"
date: 2023-10-31T01:00:00Z
draft: true
author: Andrew Pollock and Oliver Chang
---
The OSV team is committed to bringing our users comprehensive, accurate and timely open source vulnerability information. Over the last year, the OSV team has released a number of new features in pursuit of this goal including:
- [OSV-Scanner’s call graph analysis for Go and Rust](https://google.github.io/osv-scanner/experimental/#scanning-with-call-analysis)
- [New ecosystems to the database](https://osv.dev/blog/posts/almalinux-and-rocky-linux-join-osv/)
- The [new determineversion API](https://osv.dev/blog/posts/using-the-determineversion-api/), which helps C/C++ developers match their dependencies to known vulnerabilities

Today we are excited to announce the broad availability of vulnerable commit ranges into the OSV database. **Vulnerable commit ranges, along with the previously announced experimental determineversion API, will enable vulnerability management for software with C and C++ dependencies, which has been one of the last gaps in coverage in OSV.dev’s database.**
<!--more-->

## What are vulnerable commit ranges??

![Image shows the vulnerable commit ranges for CVE-2023-26130. More information is available in the "Submoduled C/C++ dependencies" section.](commit-range.png "Vulnerable commit ranges for CVE-2023-26130")

Typically open source dependencies are matched to known vulnerabilities by versions according to a package registry (e.g. npm, PyPI). Vulnerable commit ranges provide a granular approach  that more closely follows the development process, matching vulnerabilities to a range of upstream commits.

### Augmenting the NVD CVE database

We've built up a database of 30,000 advisories based on the [NVD CVE database](https://nvd.nist.gov/vuln/search). We enrich the data from NVD with vulnerable commit ranges through algorithmic analysis performed by OSV.dev that matches  git repository tag information to patch information supplied by the CVE. 

As part of our work in this area, we've established working relationships with the NVD via data quality fixes and longer term systematic improvements.

### Advantages to OSV’s users

The benefits of vulnerable commit range information include:

- Identification of vulnerable C and C++ software
- Commit-level vulnerability scanning of source code (regardless of language)
- Easier identification of Git branches cut from known-vulnerable commits

## Vulnerabilities in C/C++ dependencies

Matching C/C++ dependencies to known vulnerabilities has been one of the final pieces in the puzzle of a truly comprehensive open source vulnerability database. Because the C/C++ ecosystem does not have a centralized package manager, source code identifiers (e.g. git hashes) are the best way to identify C/C++ libraries. Typically vulnerabilities are associated with versions, not git hashes, making C/C++ vulnerability matching difficult. The new commit level vulnerability information will allow users to confidently match their dependencies to known vulnerabilities within the OSV database. 

It is common for C/C++ projects to include their open source dependencies within their project and this is typically accomplished one of two ways:

- Submoduled dependencies retain their git histories. It is easy to determine the current git commit of each dependency. 
- Vendored dependencies are copied into the project but do not retain their git histories. It is difficult to determine the dependency version and therefore difficult to determine relevant vulnerabilities. 

Between our commit level vulnerability information and our previously released determineversion API, OSV is able to help you match your dependencies to vulnerabilities regardless of whether your project has submoduled or vendored dependencies. 

### Submoduled C/C++ dependencies

Let’s take a look at the [pd-server](https://github.com/charlesneimog/pd-server) project. Pd-server is a PureData interface to cpp-httplib and includes cpp-httplib as a submoduled dependency. For this example, we will be working from `cf3f15a841ca21b53c6de654c9981a30ae0b590c`. If you want to follow along with this example, make sure that HEAD is pointed to this specific commit. 

To determine whether pd-server’s cpp-httplib copy has any known vulnerabilities, we must first determine the copy’s most recent commit hash by following these steps in your terminal:

1. Recursively clone the pd-server project to your local machine using `git clone --recursive https://github.com/charlesneimog/pd-server`
2. Navigate into the pd-server project folder using `cd pd-server`
3. Use `git submodule status` to determine the most recent commits for each submodule. 

```
git clone --recursive https://github.com/charlesneimog/pd-server
cd pd-server
git submodule status
 5c2e137f7a7a03f4007494954ccb3e23753e7807 pd-lib-builder (v0.6.0-28-g5c2e137)
 227d2c20509f85a394133e2be6d0b0fc1fda54b2 src/cpp-httplib (v0.11.3-6-g227d2c2)
 4c6cde72e533158e044252718c013a48bcff346c src/json (v3.11.2-39-g4c6cde72)
 1b11fd301531e6df35a6107c1e8665b1e77a2d8e src/websocketpp (0.8.2-1-g1b11fd3)
```

We can see that the cpp-httplib’s most recent commit hash is `227d2c20509f85a394133e2be6d0b0fc1fda54b2`. We can now use this information to construct an API call. It will be in this form:

```
curl -d \
  '{"commit": "227d2c20509f85a394133e2be6d0b0fc1fda54b2"}' \
  "https://api.osv.dev/v1/query" | jq '.vulns | map(.id)'
```

 Which returns:

```
[
  "CVE-2023-26130"
]
```

From this result, we can conclude that the pd-server project is vulnerable to [CVE-2023-26130](https://osv.dev/vulnerability/CVE-2023-26130) through its use of cpp-httplib. Fortunately cpp-httplib has a fix. If pd-server updated their copy of cpp-httplib to [this commit](https://github.com/yhirose/cpp-httplib/commit/5b397d455d25a391ba346863830c1949627b4d08), the project would no longer be vulnerable to CVE-2023-26130. 

### Vendored C/C++ dependencies

The determineversion API is the first step to finding vulnerabilities within your vendored dependencies. Vendored dependencies do not include git or version information, but the determineversion API estimates your dependency by comparing files hashes from your local project to known hashes for a given version. When we released the API in July, its use was limited to vulnerabilities found by OSS-Fuzz. Not all C/C++ projects are part of OSS-Fuzz, nor are all vulnerabilities for a given dependency found by OSS-Fuzz, so a number of vulnerabilities were left on the table. 

With the addition of the commit level vulnerability data from the NVD, this gap has been significantly narrowed. This means that the determineversion API may be used for the majority of vendored C/C++ dependencies. Once your dependency version is known, you can find the relevant vulnerabilities through searching our database or using our API. For more information on how to use the determineversion API, please see our [documentation](https://google.github.io/osv.dev/post-v1-determineversion/) or this [walkthrough](https://google.github.io/osv.dev/post-v1-determineversion/). 

Within the next few months, support will be added to OSV-Scanner to make this a seamless out of the box experience for developers. 

Try it yourself!

Do you have a project that uses C/C++ dependencies? We encourage you to try our new vulnerable commit range features and [let us know](https://github.com/google/osv.dev/issues/new/) about your experience. If you encounter a data issue, please fill out a [data quality report](https://github.com/google/osv.dev/issues/new?assignees=&labels=data+quality&projects=&template=converted-nvd-cve-data-quality-report.md&title=Data+quality+issue+with+CVE-yyyy-nnnn). Your contributions, questions, and feedback will help us improve not only the quality of our data, but will ultimately help users identify and fix vulnerabilities in their projects. 