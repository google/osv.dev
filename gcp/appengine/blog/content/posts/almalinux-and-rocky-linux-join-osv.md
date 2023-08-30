---
title: "AlmaLinux and Rocky Linux join OSV"
date: 2023-05-08T16:00:00Z
draft: false
author: OSV Team
---

Two new Linux distributions have been added to the OSV database. With the addition of [AlmaLinux](https://almalinux.org/) and [Rocky Linux](https://rockylinux.org/), the OSV database is now made up of advisories from 18 sources, including language ecosystems and Linux distributions.
<!--more-->

AlmaLinux and Rocky Linux were both started in response to CentOS moving upstream of Red Hat Enterprise Linux® (RHEL). These distros are open source, community driven, and 100% compatible with RHEL. Both maintainer teams worked closely with the OSV team to bring their advisories into the database. We’d like to thank them for their hard work! We know our community will benefit from their data contributions. 

If you work with a project (like a Linux distribution) and would like to contribute data, we’d love to help get your data into OSV. Details of the process are available [here](https://github.com/google/osv.dev/blob/master/CONTRIBUTING.md#contributing-data).

```json
{
  "schema_version": "1.3.0",
  "id": "GHSA-c3g4-w6cv-6v7h",
  "modified": "2022-04-01T13:56:42Z",
  "published": "2022-04-01T13:56:42Z",
  "aliases": [ "CVE-2022-27651" ],
  "summary": "Non-empty default inheritable capabilities for linux container in Buildah",
  "details": "A bug was found in Buildah where containers were created ...",
  "affected": [
    {
      "package": {
        "ecosystem": "Go",
        "name": "github.com/containers/buildah"
      },
      "ranges": [
        {
          "type": "SEMVER",
          "events": [
            {
              "introduced": "0"
            },
            {
              "fixed": "1.25.0"
            }
          ]
        }
      ]
    }
  ],
  "references": [
    {
      "type": "WEB",
      "url": "https://github.com/containers/buildah/commit/..."
    },
    {
      "type": "PACKAGE",
      "url": "https://github.com/containers/buildah"
    }
  ]
}
```