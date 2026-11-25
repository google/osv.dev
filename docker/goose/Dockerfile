FROM golang:1.27.4-alpine@sha256:70bd7ddea8b6cbe5d6943cde279d6b67feb10cc924fb9100d1d8757c1575b280 AS GO_BUILD

ARG GOOSE_VERSION=3.28.0
ARG CLOUD_SQL_PROXY_VERSION=2.26.0
WORKDIR /build/
RUN GOBIN=$(pwd) go install \
  -tags='no_clickhouse no_libsql no_mssql no_mysql no_redshift no_sqlite3 no_turso no_vertica no_ydb' \
  github.com/pressly/goose/v3/cmd/goose@v${GOOSE_VERSION}
RUN GOBIN=$(pwd) go install \
  github.com/GoogleCloudPlatform/cloud-sql-proxy/v2@v${CLOUD_SQL_PROXY_VERSION}

FROM gcr.io/google.com/cloudsdktool/google-cloud-cli:alpine@sha256:31e27958892650f753ecf6fab1c4aebc4f0bfdc55c6364da8902c62b852791cf

COPY --from=GO_BUILD /build/goose /usr/bin/goose
COPY --from=GO_BUILD /build/cloud-sql-proxy /usr/bin/cloud-sql-proxy
COPY entrypoint.bash /builder/entrypoint.bash
RUN chmod +x /builder/entrypoint.bash

ENTRYPOINT ["/builder/entrypoint.bash"]
