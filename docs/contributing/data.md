---
layout: page
title: Contributing Data
permalink: /data/
nav_order: 3
has_children: false
---
# Contributing Data

Data contributions are welcome. If you work with a project such as a Linux distribution
 or other open source project and would like to contribute your security advisories,
please follow these steps:

- [ ] Decide if you're going to publish records via a [Git repository](/git-repo-contribution), [GCS bucket](/gcs-bucket-contribution/) or [REST endpoint](/rest-api-contribution/).
- [ ] Open an [issue](https://github.com/google/osv.dev/issues). Let us know about your project and tag the issue `datasource` so we can properly triage the issue.
- [ ] Prepare your data - refer to the [OSV Schema](https://ossf.github.io/osv-schema/) documentation for information on how to properly format the data so it can be accepted. 
- [ ] Create a PR to [reserve a prefix in the OSV-Schema](https://ossf.github.io/osv-schema/#id-modified-fields). We review the records you start publishing for OSV Schema [correctness](https://github.com/ossf/osv-schema/tree/main/validation) and [quality](https://google.github.io/osv.dev/data_quality.html) as part of reviewing and merging this PR.

  **Worked Examples:**
  -  https://github.com/ossf/osv-schema/pull/235
  -  https://github.com/ossf/osv-schema/pull/223
  -  https://github.com/ossf/osv-schema/pull/219

- [ ] Create a PR to extend [purl_helpers.py](https://github.com/google/osv.dev/blob/master/osv/purl_helpers.py) (if appropriate)
  
- [ ] Create a PR to start [importing the records you are publishing into our test instance of OSV.dev](https://github.com/google/osv.dev/blob/master/source_test.yaml) and validate everything is working as intended there (worked example: https://github.com/google/osv.dev/pull/2086)

- [ ] Create a PR to start [importing the records you are publishing into our production environment](https://github.com/google/osv.dev/blob/master/source.yaml)
  
  **Worked example:**
  - https://github.com/google/osv.dev/pull/2105)


Do you have a question, suggestion or feedback? Please [open an issue](https://github.com/google/osv.dev/issues). 