---
layout: page
title: New Data Source
permalink: /data/new
nav_order: 1
has_children: true
parent: Data sources
---

# Contributing A New Data Source

Data contributions are welcome. OSV.dev readily accepts security related records from open source projects, given they are provided in the [OSV format](https://ossf.github.io/osv-schema/). Publishing records to OSV is straightforward: reserve a prefix in the OSV-Schema, and then prepare and publish your data via a Git repository or other supported method. 

The step by step instructions are as follows:

- [ ] Open an [issue](https://github.com/google/osv.dev/issues) using the 'new data source' template.  
        
- [ ] Prepare your data \- refer to the [OSV Schema](https://ossf.github.io/osv-schema/) documentation for information on how to properly format the data so it can be accepted.  
        
- [ ] Create a PR to [reserve an ID prefix and define a new ecosystem](https://ossf.github.io/osv-schema/#id-modified-fields) ([example](https://github.com/ossf/osv-schema/pull/351)). We review the records you start publishing for OSV Schema [correctness](https://github.com/ossf/osv-schema/tree/main/validation) and [quality](https://google.github.io/osv.dev/data_quality.html) as part of reviewing and merging this PR.

- [ ] Prepare and publish your records via a public Git repository ([example](https://github.com/AlmaLinux/osv-database/tree/master)). If this method isn’t ideal, we also support publishing records through [REST API](/data/new/rest-api) or GCS buckets ([example](https://storage.googleapis.com/android-osv/)).  
        
- [ ] To support API querying, if you are contributing a new ecosystem, please create a PR to extend [purl\_helpers.py](https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py) and create a new ecosystem in [\_ecosystems.py](https://github.com/google/osv.dev/blob/master/osv/ecosystems/_ecosystems.py). You can refer to existing examples showing how to implement support for [Semver](https://github.com/google/osv.dev/blob/139de7b69a2ea39e2113309b3a0a47aab920ddcf/osv/ecosystems/_ecosystems.py#L45) and [non-Semver](https://github.com/google/osv.dev/pull/3430) ecosystems.  
        
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there.

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml)


<details markdown="1">
<summary><b>source.yaml Examples</b></summary>

### Git (preferred)
``` yaml
- name: 
  type: 0   # 0: GIT, 1: GCS, 2: REST
  repo_url:    # The repo URL for the source
  db_prefix: # DB prefix, if the database allocates its own. https://ossf.github.io/osv-schema/#id-modified-fields
  human_link: # HTTP link prefix to individual vulnerability records for humans. 
  link: # HTTP link prefix to individual OSV source records. 
  directory_path: # Vulnerability data not under this path is ignored by the importer.
  extension: '.json' # Default extension.
  ignore_patterns: # Patterns of files to exclude (regex).
```
Advanced and optional fields 
``` yaml
  # Optional
  repo_username:  # The username to use for SSH auth if needed
  repo_branch: # Optional branch for repo
  
  # Default Advanced values
  editable: False # Whether this repository is editable.
  ignore_git: False # If true, don't analyze any Git ranges.
  detect_cherrypicks: False # Whether to detect cherrypicks or not (slow for large repos).
  consider_all_branches: False # Whether to consider all branches when analyzing GIT ranges.
  versions_from_repo: False # Whether to populate "affected[].versions" from Git ranges.
  strict_validation: False # Apply strict validation (JSON Schema + linter checks) to this source.
```

### REST
``` yaml
- name: 
  type: 2 # 0: GIT, 1: GCS, 2: REST
  rest_api_url: # URL pointing to a REST endpoint containing at least all of the vulnerabilities' IDs and date modified
  db_prefix: # DB prefix, as reserved in ossf. https://ossf.github.io/osv-schema/#id-modified-fields
  human_link: # The human readable link
  link:  # The base link
  directory_path: # Vulnerability data not under this path is ignored by the importer
  extension: # Extension for vulnerability data
  ignore_patterns:  # Patterns of files to exclude (regex).
```
Advanced and optional fields 
``` yaml
  detect_cherrypicks: False # Whether to detect cherrypicks or not (slow for large repos)
  ignore_git: False # If true, don't analyze any Git ranges.
  editable: False # Whether this repository is editable.
  versions_from_repo: False # Whether to populate "affected[].versions" from Git ranges.
  strict_validation: False # Apply strict validation (JSON Schema + linter checks) to this source.
```

### GCS
``` yaml
- name: 
  type: 1 # 0: GIT, 1: GCS, 2: REST
  bucket:  # Bucket name
  db_prefix:  # DB prefix, as reserved in ossf. https://ossf.github.io/osv-schema/#id-modified-fields
  human_link:  # The human readable link
  link:  # The base link
  directory_path: # Vulnerability data not under this path is ignored by the importer
  extension: '.json' # Extension for vulnerability data
  ignore_patterns: # Patterns of files to exclude (regex).

```
Advanced and optional fields 
``` yaml
  detect_cherrypicks: False # Whether to detect cherrypicks or not (slow for large repos)
  ignore_git: False # If true, don't analyze any Git ranges.
  editable: False # Whether this repository is editable.
  versions_from_repo: False # Whether to populate "affected[].versions" from Git ranges.
  strict_validation: False # Apply strict validation (JSON Schema + linter checks) to this source.
```

</details>
Do you have a question, suggestion or feedback? Please [open an issue](https://github.com/google/osv.dev/issues).