# Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

FROM golang:1.23.3-alpine@sha256:25db3a0508ff009054bf467f25e1ab395fced0f93b69459dd736ae523e61c781 AS GO_BUILD

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:5fb06d62786edacb958f6d5a8a993eac3b747d84a7ca3c6433ae1f9a6df098e1

COPY --from=GO_BUILD /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
