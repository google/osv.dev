---
name: New datasource
about: Set up a new data source to be ingested into OSV.dev 
title: ''
labels: datasource
assignees: ''

---
- [ ] Decide how you are going to publish records: [Git repository](/git-repo-contribution) | [GCS bucket](/gcs-bucket-contribution/) | [REST endpoint](/rest-api-contribution/): 
- [ ] Prepare your data - refer to the [OSV Schema](https://ossf.github.io/osv-schema/) documentation for information on how to properly format the data so it can be accepted. 
- [ ] Create a PR to [reserve a prefix in the OSV-Schema](https://ossf.github.io/osv-schema/#id-modified-fields). We review the records you start publishing for OSV Schema [correctness](https://github.com/ossf/osv-schema/tree/main/validation) and [quality](https://google.github.io/osv.dev/data_quality.html) as part of reviewing and merging this PR.

- [ ] Create a PR to extend [purl_helpers.py](https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py) (if appropriate)
  
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there.

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml).
