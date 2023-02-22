Steps taken to set up:

0. Enable Cloud Deploy API from project (`clouddeploy.googleapis.com`)
0. `gcloud deploy apply --file=clouddeploy.yaml --region=us-central1 --project=oss-vdb`

To delete:
```
gcloud deploy delete --file=clouddeploy.yaml --force --region=us-central1 --project=oss-vdb
```