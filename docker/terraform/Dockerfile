# Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

FROM golang:1.24.0-alpine@sha256:2d40d4fc278dad38be0777d5e2a88a2c6dee51b0b29c97a764fc6c6a11ca893c AS GO_BUILD

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:9c9ba04595e3917dfd1bdb3a1d1d9465eab4bde79bf5eac6e6a9721ea8cdecc1

COPY --from=GO_BUILD /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
