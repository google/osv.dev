-- name: GetVulnerabilityProtos :many
SELECT id, proto
FROM vulnerabilities
WHERE id = ANY(@ids::text[]);

-- name: GetVulnerabilityModified :many
SELECT id, (data->>'modified')::timestamptz AS modified
FROM vulnerabilities
WHERE id = ANY(@ids::text[]);

-- name: MatchPackageVersionedWithEcosystem :batchmany
SELECT id, vuln_id, versions, events
FROM affected_versions
WHERE name = @name
  AND base_ecosystem = @base_ecosystem
  AND (vuln_id, id) > (@after_vuln_id::text, @after_row_id::bigint)
  AND coarse_min <= @coarse_upper
  AND coarse_max >= @coarse_lower
  AND @ecosystem::text = ANY(ecosystems)
ORDER BY vuln_id, id
LIMIT @row_limit;

-- name: MatchPackageVersionedNoEcosystem :batchmany
SELECT id, vuln_id, base_ecosystem, versions, events
FROM affected_versions
WHERE name = @name
  AND (vuln_id, id) > (@after_vuln_id::text, @after_row_id::bigint)
ORDER BY vuln_id, id
LIMIT @row_limit;

-- name: MatchPackageVersionless :batchmany
SELECT DISTINCT vuln_id
FROM affected_versions
WHERE name = @name
  AND base_ecosystem = @base_ecosystem
  AND vuln_id > @after_vuln_id
  AND @ecosystem::text = ANY(ecosystems)
ORDER BY vuln_id
LIMIT @row_limit;

-- name: MatchCommits :batchmany
SELECT vuln_id
FROM affected_commits
WHERE commit_sha = @commit_sha
  AND vuln_id > @after_vuln_id
ORDER BY vuln_id
LIMIT @row_limit;
