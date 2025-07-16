# Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

FROM golang:1.24.5-alpine@sha256:48ee313931980110b5a91bbe04abdf640b9a67ca5dea3a620f01bacf50593396 AS GO_BUILD

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:f0f43981a0b69a5d6390a1e9cc47e2355a873e1c1e9d6d1b923cbded92bda671

COPY --from=GO_BUILD /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
