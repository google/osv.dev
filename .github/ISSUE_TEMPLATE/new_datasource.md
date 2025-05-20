---
name: New datasource
about: Set up a new data source to be ingested into OSV.dev 
title: ''
labels: datasource
assignees: ''

---
- [ ] Prepare your data \- refer to the [OSV Schema](https://ossf.github.io/osv-schema/) documentation for information on how to properly format the data so it can be accepted.  
        
- [ ] Create a PR to [reserve a prefix in the OSV-Schema](https://ossf.github.io/osv-schema/#id-modified-fields) ([example](https://github.com/ossf/osv-schema/pull/219)). We review the records you start publishing for OSV Schema [correctness](https://github.com/ossf/osv-schema/tree/main/validation) and [quality](https://google.github.io/osv.dev/data_quality.html) as part of reviewing and merging this PR.

- [ ] Prepare and publish your records via a [Git repository](http:///git-repo-contribution) ([example](https://github.com/AlmaLinux/osv-database/tree/master)). If this method isn’t ideal, we also support publishing records from [GCS bucket](http:///gcs-bucket-contribution/) ([example](https://storage.googleapis.com/android-osv/)) or [REST endpoint](http:///rest-api-contribution/).  
        
- [ ] To support API querying, please create a PR to extend [purl\_helpers.py](https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py) and create a new ecosystem in [\_ecosystems.py](https://github.com/google/osv.dev/blob/master/osv/ecosystems/_ecosystems.py). You can refer to existing examples showing how to implement support for [Semver](https://github.com/google/osv.dev/blob/139de7b69a2ea39e2113309b3a0a47aab920ddcf/osv/ecosystems/_ecosystems.py#L45) and [non-Semver](https://github.com/google/osv.dev/pull/3430) ecosystems.  
        
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there.

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml)