---
layout: page
title: New Data Source
permalink: /data/new
nav_order: 1
has_children: true
parent: Data sources
---

# Contributing A New Data Source

Data contributions are welcome. OSV.dev readily accepts security related records from open source projects, given they are provided in the [OSV format](https://ossf.github.io/osv-schema/). Publishing records to OSV is straightforward: reserve a prefix in the OSV-Schema, and then prepare and publish your data via a Git repository or other supported method. The step by step instructions are as follows:

- [ ] Open an [issue](https://github.com/google/osv.dev/issues) using the 'new data source' template.  
        
- [ ] Prepare your data \- refer to the [OSV Schema](https://ossf.github.io/osv-schema/) documentation for information on how to properly format the data so it can be accepted.  
        
- [ ] Create a PR to [reserve a prefix in the OSV-Schema](https://ossf.github.io/osv-schema/#id-modified-fields) ([example](https://github.com/ossf/osv-schema/pull/219)). We review the records you start publishing for OSV Schema [correctness](https://github.com/ossf/osv-schema/tree/main/validation) and [quality](https://google.github.io/osv.dev/data_quality.html) as part of reviewing and merging this PR.

- [ ] Prepare and publish your records via a public Git repository ([example](https://github.com/AlmaLinux/osv-database/tree/master)). If this method isn’t ideal, we also support publishing records from GCS bucket ([example](https://storage.googleapis.com/android-osv/)) or [REST endpoint](/data/new/rest-api).  
        
- [ ] To support API querying, please create a PR to extend [purl\_helpers.py](https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py) and create a new ecosystem in [\_ecosystems.py](https://github.com/google/osv.dev/blob/master/osv/ecosystems/_ecosystems.py). You can refer to existing examples showing how to implement support for [Semver](https://github.com/google/osv.dev/blob/139de7b69a2ea39e2113309b3a0a47aab920ddcf/osv/ecosystems/_ecosystems.py#L45) and [non-Semver](https://github.com/google/osv.dev/pull/3430) ecosystems.  
        
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there.

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml)


<details markdown="1">
<summary><b>source.yaml Examples</b></summary>

### Git (preferred)
``` yaml
- name: # name of advisory
  type: 0   # 0: GIT, 1: GCS, 2: REST
  repo_url:    # The repo URL for the source
  repo_username:  # The username to use for SSH auth if needed
  repo_branch: # Optional branch for repo
  directory_path: # Vulnerability data not under this path is ignored by the importer.
  ignore_patterns: # Patterns of files to exclude (regex).
  editable: # Whether this repository is editable.
  extension: # Default extension.
  key_path: # Key path within each file to store the vulnerability. 
  ignore_git: # If true, don't analyze any Git ranges.
  detect_cherrypicks: # Whether to detect cherrypicks or not (slow for large repos).
  consider_all_branches: # Whether to consider all branches when analyzing GIT ranges.
  versions_from_repo: # Whether to populate "affected[].versions" from Git ranges.
  link: # HTTP link prefix to individual OSV source records. 
  human_link: # HTTP link prefix to individual vulnerability records for humans. 
  db_prefix: # DB prefix, if the database allocates its own.
  # https://ossf.github.io/osv-schema/#id-modified-fields
  strict_validation: # Apply strict validation (JSON Schema + linter checks) to this source.
```

### GCS
``` yaml
- name: 
  versions_from_repo:  # Whether to populate "affected[].versions" from Git ranges.
  type: 1 # 0: GIT, 1: GCS, 2: REST
  ignore_patterns: # Patterns of files to exclude (regex).
  directory_path: # Vulnerability data not under this path is ignored by the importer
  detect_cherrypicks:  # Whether to detect cherrypicks or not (slow for large repos)
  extension: # Extension for vulnerability data
  bucket:  # Bucket name
  db_prefix:  # DB prefix, as reserved in ossf. https://ossf.github.io/osv-schema/#id-modified-fields
  ignore_git:  # If true, don't analyze any Git ranges.
  human_link:  # The human readable link
  link:  # The base link
  editable:  # Whether this repository is editable.
  strict_validation: # Apply strict validation (JSON Schema + linter checks) to this source.
```

### REST
``` yaml
- name: # name of source
  versions_from_repo: # Whether to populate "affected[].versions" from Git ranges.
  rest_api_url: # URL pointing to a REST endpoint containing at least all of the vulnerabilities' IDs and date modified
  type: 2 # 0: GIT, 1: GCS, 2: REST
  ignore_patterns:  # Patterns of files to exclude (regex).
  directory_path: # Vulnerability data not under this path is ignored by the importer
  detect_cherrypicks: # Whether to detect cherrypicks or not (slow for large repos)
  extension: # Extension for vulnerability data
  db_prefix: # DB prefix, as reserved in ossf. https://ossf.github.io/osv-schema/#id-modified-fields
  ignore_git: False # If true, don't analyze any Git ranges.
  human_link: # The human readable link
  link:  # The base link
  editable: # Whether this repository is editable.
  strict_validation: # Apply strict validation (JSON Schema + linter checks) to this source.
```
</details>
Do you have a question, suggestion or feedback? Please [open an issue](https://github.com/google/osv.dev/issues).