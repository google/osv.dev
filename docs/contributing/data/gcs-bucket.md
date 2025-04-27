---
layout: page
title: Contributing Data from GCS Bucket
permalink: /contributing/data/gcs-bucket/
nav_order: 1
parent: Contributing Data
---
# Contributing Data from GCS Bucket

Contributing data can be supplied either through a public Git repository, a public GCS bucket or to REST API endpoints. The below guidelines are for contributing data through a **GCS Bucket**.

Examples of current data sources using a GCS bucket are:

Example source.yaml for a GCS Bucket:

```yaml
- name: 'go'
  versions_from_repo: True
  type: 1
  ignore_patterns: ['^(?!GO-).*$']
  directory_path: 'ID'
  detect_cherrypicks: True
  extension: '.json'
  bucket: 'go-vulndb'
  db_prefix: ['GO-']
  ignore_git: True
  human_link: 'https://pkg.go.dev/vuln/{{ BUG_ID }}'
  link: 'https://vuln.go.dev/'
  editable: False
  strict_validation: True
```



### Open an issue [here](https://github.com/google/osv.dev/issues).
