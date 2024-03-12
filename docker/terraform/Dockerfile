# Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

FROM golang:1.22.1-alpine@sha256:5a99b4049412cd34ad6b4e0c9527ae6beb9ae82d787b4bf3f4eff7aa13fc577a AS GO_BUILD

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/google.com/cloudsdktool/cloud-sdk:alpine

COPY --from=GO_BUILD /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
