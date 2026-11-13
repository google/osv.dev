FROM golang:1.27.3-alpine@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS GO_BUILD

ARG GOOSE_VERSION=3.28.0
ARG CLOUD_SQL_PROXY_VERSION=2.26.0
WORKDIR /build/
RUN GOBIN=$(pwd) go install \
  -tags='no_clickhouse no_libsql no_mssql no_mysql no_redshift no_sqlite3 no_turso no_vertica no_ydb' \
  github.com/pressly/goose/v3/cmd/goose@v${GOOSE_VERSION}
RUN GOBIN=$(pwd) go install \
  github.com/GoogleCloudPlatform/cloud-sql-proxy/v2@v${CLOUD_SQL_PROXY_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:269c3ae5175a900ea6be98322dcc65d4cb1499ec9f8f262d19bbd128c6a898c8

COPY --from=GO_BUILD /build/goose /usr/bin/goose
COPY --from=GO_BUILD /build/cloud-sql-proxy /usr/bin/cloud-sql-proxy
COPY entrypoint.bash /builder/entrypoint.bash
RUN chmod +x /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
