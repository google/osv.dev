FROM golang:1.19 AS build

ARG TERRAFORM_VERSION
WORKDIR /build/
RUN GOBIN=$(pwd) go install github.com/hashicorp/terraform@v${TERRAFORM_VERSION}

FROM gcr.io/cloud-builders/gcloud

COPY --from=build /build/terraform /usr/bin/terraform
COPY entrypoint.bash /builder/entrypoint.bash
ADD https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64 /usr/bin/jq
RUN chmod a+x /usr/bin/jq

ENTRYPOINT ["/builder/entrypoint.bash"]
