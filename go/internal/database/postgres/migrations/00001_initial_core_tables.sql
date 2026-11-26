-- +goose Up
CREATE TABLE raw_vulnerabilities (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vuln_id TEXT COLLATE "C",
    source_id TEXT COLLATE "C" NOT NULL,
    source_path TEXT COLLATE "C" NOT NULL,
    content_sha256 BYTEA NOT NULL,
    git_commit_hash TEXT COLLATE "C",
    gcs_generation BIGINT,
    raw_data JSONB NOT NULL,
    fetched_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_raw_vuln_source_hash UNIQUE (source_id, source_path, content_sha256)
);

CREATE INDEX idx_raw_vuln_lookup ON raw_vulnerabilities (source_id, source_path, fetched_at DESC);

CREATE TABLE vulnerabilities (
    id TEXT COLLATE "C" NOT NULL,
    revision INT NOT NULL DEFAULT 1,
    source_id TEXT COLLATE "C" NOT NULL,
    source_path TEXT COLLATE "C" NOT NULL,
    raw_vuln_id BIGINT REFERENCES raw_vulnerabilities(id),
    modified TIMESTAMPTZ NOT NULL,
    source_modified TIMESTAMPTZ,
    withdrawn TIMESTAMPTZ,
    alias_raw TEXT[] COLLATE "C",
    related_raw TEXT[] COLLATE "C",
    upstream_raw TEXT[] COLLATE "C",
    data JSONB NOT NULL,
    proto BYTEA NOT NULL,
    PRIMARY KEY (id) INCLUDE (modified)
);

-- Fast covering lookup by source and path for reconciliation and ListBySource
CREATE INDEX idx_vulns_source ON vulnerabilities (source_id, source_path) INCLUDE (id, source_modified, withdrawn);

-- Modified time index for feed sync and incremental exporters
CREATE INDEX idx_vulns_modified ON vulnerabilities (modified DESC);

-- Partial index for fast filtering of withdrawn records
CREATE INDEX idx_vulns_withdrawn ON vulnerabilities (withdrawn) WHERE withdrawn IS NOT NULL;

-- Partial GIN indexes for relations computation (ignoring empty arrays and withdrawn records)
CREATE INDEX idx_vulns_alias_raw ON vulnerabilities USING GIN (alias_raw) WHERE cardinality(alias_raw) > 0 AND withdrawn IS NULL;
CREATE INDEX idx_vulns_related_raw ON vulnerabilities USING GIN (related_raw) WHERE cardinality(related_raw) > 0 AND withdrawn IS NULL;
CREATE INDEX idx_vulns_upstream_raw ON vulnerabilities USING GIN (upstream_raw) WHERE cardinality(upstream_raw) > 0 AND withdrawn IS NULL;

-- vuln_id does not reference vulnerabilities(id) so that if a vulnerability row
-- ever needs to be hard-deleted, its historical audit trail is preserved.
CREATE TABLE historic_vulnerabilities (
    vuln_id TEXT COLLATE "C" NOT NULL,
    revision INT NOT NULL,
    raw_vuln_id BIGINT REFERENCES raw_vulnerabilities(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    data JSONB NOT NULL,
    PRIMARY KEY (vuln_id, revision)
);

-- vuln_id does not reference vulnerabilities(id) because there is no index on (vuln_id)
-- (to save space/writes), which would cause a full table scan on vulnerability deletes.
-- Use vuln_commits to look up commits and delete by (commit_sha, vuln_id).
CREATE TABLE affected_commits (
    commit_sha BYTEA NOT NULL,
    vuln_id TEXT COLLATE "C" NOT NULL,
    PRIMARY KEY (commit_sha, vuln_id)
);

CREATE TABLE vuln_commits (
    vuln_id TEXT COLLATE "C" PRIMARY KEY REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    commits BYTEA[]
);

CREATE TABLE affected_versions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vuln_id TEXT COLLATE "C" NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    name TEXT COLLATE "C" NOT NULL,
    base_ecosystem TEXT COLLATE "C" NOT NULL,
    ecosystems TEXT[] COLLATE "C" NOT NULL,
    coarse_min TEXT COLLATE "C" NOT NULL,
    coarse_max TEXT COLLATE "C" NOT NULL,
    versions TEXT[] COLLATE "C",
    events JSONB
);

-- Primary index for typical queries (with ecosystem provided)
CREATE INDEX idx_affected_versions_match
ON affected_versions (name, base_ecosystem, vuln_id, id, coarse_min, coarse_max)
INCLUDE (ecosystems);

-- Secondary index for queries without ecosystems
CREATE INDEX idx_affected_versions_name_only
ON affected_versions (name, vuln_id, id);

-- Index for worker updates/deletes by vuln_id
CREATE INDEX idx_affected_versions_vuln_id ON affected_versions (vuln_id);

-- +goose Down
DROP TABLE affected_versions;
DROP TABLE vuln_commits;
DROP TABLE affected_commits;
DROP TABLE historic_vulnerabilities;
DROP TABLE vulnerabilities;
DROP TABLE raw_vulnerabilities;
