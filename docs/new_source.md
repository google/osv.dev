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

- [ ] Prepare and publish your records via a public Git repository ([example](https://github.com/AlmaLinux/osv-database/tree/master)). If this method isn’t ideal, we also support publishing records through [REST API](./rest-api.md) or GCS buckets ([example](https://storage.googleapis.com/android-osv/)). Ensure your data is published under a clearly documented license that meets our [data licensing requirements](#data-licensing).  
        
- [ ] To support API querying, if you are contributing a new ecosystem, please create a PR to add PURL mappings in [go/purl](https://github.com/google/osv.dev/tree/master/go/purl) and register the ecosystem version logic in [go/osv/ecosystem](https://github.com/google/osv.dev/tree/master/go/osv/ecosystem) (see [ecosystem factories](https://github.com/google/osv.dev/blob/9d4d7192f3a2a5bb4aa62ff31bd803d63e0026fb/go/osv/ecosystem/ecosystem.go#L41)). You can refer to existing examples for [Semver](https://github.com/google/osv.dev/blob/master/go/osv/ecosystem/semver.go) and non-Semver (e.g. [Debian](https://github.com/google/osv.dev/blob/master/go/osv/ecosystem/debian.go)) ecosystems.  
  *Note: Many of our ecosystems rely on [osv-scalibr's semantic module](https://github.com/google/osv-scalibr/tree/main/semantic), which osv-scanner also uses to perform offline scanning. Consider adding it there if you wish to have the ecosystem fully supported in osv-scanner.*  
        
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there.

- [ ] After successful import, review the OSV-linter results by querying:
  ```
  https://api.test.osv.dev/v1experimental/importfindings/{source_name}
  ```
  to identify and address any important record linting issues. Note that it may take up to 24 hours for new findings to populate. You can also view this information more interactively at [test.osv.dev/linter](https://test.osv.dev/linter).

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml) and document your data source and its license in [docs/data.md](https://github.com/google/osv.dev/blob/master/docs/data.md).

## Data Licensing

When OSV.dev ingests records from a data source, it does not simply host the raw files as-is:

1. **Enrichment and Modification**: OSV.dev [enriches imported records](./faq.md#what-does-osvdev-do-to-the-records-it-imports) by enumerating affected package versions and Git commits, populating Package URLs (`purl`) and source attribution links (`database_specific.source`), and continuously computing transitive and reflective `aliases`, `upstream`, and `related` vulnerability relationships (which updates the record's `modified` timestamp).
2. **Public Redistribution**: OSV.dev serves these enriched records via the [OSV.dev website](https://osv.dev), the [OSV API](./api/index.md), and bulk [GCS data dumps](./data.md#data-dumps) (`gs://osv-vulnerabilities`, including `all.zip` and per-ecosystem archives).
3. **Downstream Consumption**: Records served by OSV.dev are consumed by open-source tools (such as [OSV-Scanner](https://github.com/google/osv-scanner)), security researchers, downstream vulnerability databases, and commercial software composition analysis (SCA) tools.

Accordingly, the license for any contributed data source **must** at minimum permit OSV.dev to ingest, index, modify (enrich), and publicly redistribute the records across these channels. To ensure downstream users and tools can freely consume the aggregated dataset without legal friction, we strongly recommend publishing vulnerability data under a standard permissive license—such as **[CC0 1.0](https://creativecommons.org/publicdomain/zero/1.0/)**, **[CC-BY 4.0](https://creativecommons.org/licenses/by/4.0/)**, **[Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0)**, or **[MIT](https://opensource.org/license/mit)**.


<details markdown="1">
<summary><b>source.yaml Examples</b></summary>

### Git (preferred)
``` yaml
- name: 
  type: 0   # 0: GIT, 1: GCS, 2: REST
  repo_url:    # The repo URL for the source
  db_prefix: # DB prefix, as reserved in ossf. https://ossf.github.io/osv-schema/#id-modified-fields
  accepted_ecosystems: # List of OSV ecosystems this datasource will provide vulnerability records for.
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
  accepted_ecosystems: # List of OSV ecosystems this datasource will provide vulnerability records for.
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
  accepted_ecosystems: # List of OSV ecosystems this datasource will provide vulnerability records for.
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