FROM ubuntu:22.04

RUN apt-get update && \
    apt-get install -y curl jq nodejs npm python3-pip

RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg && \
    apt-get update && apt-get install -y google-cloud-sdk

RUN pip3 install pipenv==2023.12.1
# Install the latest npm version 8 release (last release is in Feb 2023)
# This will take precedence over the system installed version on the PATH
RUN npm install -g npm@8

COPY --from=gcr.io/oss-vdb/ci /root/go/bin/hugo /usr/local/bin/hugo
