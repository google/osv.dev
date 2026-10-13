-- +goose Up
CREATE TABLE vulnerabilities (
  id TEXT PRIMARY KEY, -- NB: This should have COLLATE "C"
  data JSONB NOT NULL,
  proto BYTEA NOT NULL
);
CREATE TABLE affected_commits (
  commit_sha BYTEA NOT NULL,
  vuln_id TEXT NOT NULL,
  PRIMARY KEY (commit_sha, vuln_id)
);
CREATE TABLE vuln_commits (
  vuln_id TEXT PRIMARY KEY REFERENCES vulnerabilities(id) ON DELETE CASCADE,
  commits BYTEA[]
);

CREATE TABLE affected_versions (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    vuln_id TEXT NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    base_ecosystem TEXT NOT NULL,
    ecosystems TEXT[] NOT NULL,
    coarse_min TEXT COLLATE "C" NOT NULL,
    coarse_max TEXT COLLATE "C" NOT NULL,
    versions TEXT[],
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
DROP TABLE vulnerabilities;
