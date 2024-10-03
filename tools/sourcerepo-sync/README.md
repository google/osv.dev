# sourcerepo-sync

## What

Synchronise the contents of [`source.yaml`](../../source.yaml) (for Production) and
[`source_test.yaml`](../../source_test.yaml) (for Staging) with Cloud Datastore.

## Why

To reduce the need for unilateral editing of
[`SourceRepository`](https://github.com/google/osv.dev/blob/fe6155f7cfa0e5df0ae1ef20c7b16f5c20bebed1/osv/models.py#L814)
kind contents in Cloud Datastore (with attendant fat-fingering risks) and
generally best-practices around config-as-code and transparency around data
sources.

## How

See [`run_source_update.sh`](run_source_update.sh):

* Uses the `gcr.io/oss-vdb/ci` Docker image
* Validates both [the YAML contents of the pull
  request](https://github.com/google/osv.dev/blob/fe6155f7cfa0e5df0ae1ef20c7b16f5c20bebed1/tools/sourcerepo-sync/source_sync.py#L125) *and* [the existing
  content in Cloud
  Datastore](https://github.com/google/osv.dev/blob/fe6155f7cfa0e5df0ae1ef20c7b16f5c20bebed1/tools/sourcerepo-sync/source_sync.py#L134)
* Can fail non-prominently post-merge

## Operational matters

* Triggered by Cloud Build on pushes of `source.yaml` or `source_test.yaml` to
  `master`, using [source\_build.yaml](source_build.yaml)
