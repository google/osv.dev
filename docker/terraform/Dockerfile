# Taken and modified from https://github.com/GoogleCloudPlatform/cloud-builders-community/tree/master/terraform

FROM golang:1.24.5-alpine@sha256:daae04ebad0c21149979cd8e9db38f565ecefd8547cf4a591240dc1972cf1399 AS GO_BUILD

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:b219424813721ddeebaf1924a6663dbf18b1e46301c05907540d53485732bd26

COPY --from=GO_BUILD /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
