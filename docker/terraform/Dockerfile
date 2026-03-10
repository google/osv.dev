# Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

FROM golang:1.26.0-alpine@sha256:d4c4845f5d60c6a974c6000ce58ae079328d03ab7f721a0734277e69905473e5 AS GO_BUILD

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:8bc187acee15fd16d076519448b22df9dd6f34a000a3fa67e4d22e10c573bb35

COPY --from=GO_BUILD /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
