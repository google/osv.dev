---
name: New datasource
about: Set up a new data source to be ingested into OSV.dev 
title: ''
labels: datasource
assignees: ''

---
- [ ] Prepare your data \- refer to the [OSV Schema](https://ossf.github.io/osv-schema/) documentation for information on how to properly format the data so it can be accepted.  
        
- [ ] Create a PR to [reserve an ID prefix and define a new ecosystem](https://ossf.github.io/osv-schema/#id-modified-fields) ([example](https://github.com/ossf/osv-schema/pull/219)). We review the records you start publishing for OSV Schema [correctness](https://github.com/ossf/osv-schema/tree/main/validation) and [quality](https://google.github.io/osv.dev/data_quality.html) as part of reviewing and merging this PR.

- [ ] Prepare and publish your records via a Git repository ([example](https://github.com/AlmaLinux/osv-database/tree/master)). If this method isn’t ideal, we also support publishing records from [REST API endpoints](https://google.github.io/osv.dev/data/new/rest-api) or through a GCS bucket([example](https://storage.googleapis.com/android-osv/)).
        
- [ ] To support API querying, if you are contributing a new ecosystem, please create a PR to add PURL mappings in [go/purl](https://github.com/google/osv.dev/tree/master/go/purl) and register the ecosystem version logic in [go/osv/ecosystem](https://github.com/google/osv.dev/tree/master/go/osv/ecosystem) (see [ecosystem factories](https://github.com/google/osv.dev/blob/9d4d7192f3a2a5bb4aa62ff31bd803d63e0026fb/go/osv/ecosystem/ecosystem.go#L41)). You can refer to existing examples for [Semver](https://github.com/google/osv.dev/blob/master/go/osv/ecosystem/semver.go) and non-Semver (e.g. [Debian](https://github.com/google/osv.dev/blob/master/go/osv/ecosystem/debian.go)) ecosystems.  
  *Note: Many of our ecosystems rely on [osv-scalibr's semantic module](https://github.com/google/osv-scalibr/tree/main/semantic), which osv-scanner also uses to perform offline scanning. Consider adding it there if you wish to have the ecosystem fully supported in osv-scanner.*  
        
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there.

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml)