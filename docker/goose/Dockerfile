FROM golang:1.27.1-alpine@sha256:8a5910f31396cd4d89662f56c68b3ae31d374308270a1c3bd96672ee5ed43414 AS GO_BUILD

ARG GOOSE_VERSION=3.28.0
ARG CLOUD_SQL_PROXY_VERSION=2.26.0
WORKDIR /build/
RUN GOBIN=$(pwd) go install \
  -tags='no_clickhouse no_libsql no_mssql no_mysql no_redshift no_sqlite3 no_turso no_vertica no_ydb' \
  github.com/pressly/goose/v3/cmd/goose@v${GOOSE_VERSION}
RUN GOBIN=$(pwd) go install \
  github.com/GoogleCloudPlatform/cloud-sql-proxy/v2@v${CLOUD_SQL_PROXY_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:786a1537df13c54289a46507b22a411f6c71154ae0293d12adce4b9358acca63

COPY --from=GO_BUILD /build/goose /usr/bin/goose
COPY --from=GO_BUILD /build/cloud-sql-proxy /usr/bin/cloud-sql-proxy
COPY entrypoint.bash /builder/entrypoint.bash
RUN chmod +x /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
