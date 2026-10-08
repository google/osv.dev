package strategies

// Strategy Pipeline Presets for different CNAs

// Default returns the default strategy pipeline for CNAs without a custom preset.
// Example: test_data/cvelistV5/cves/2025/1xxx/CVE-2025-1110.json (GitLab),
// test_data/cvelistV5/cves/2026/67xxx/CVE-2026-67185.json (VulnCheck)
func Default() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&CPEVersionStringStrategy{},
		&VersionTextExtractionStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

// GitHub returns the strategy pipeline for GitHub_M / GitHub advisories.
// Example: test_data/cvelistV5/cves/2023/45xxx/CVE-2023-45803.json,
// test_data/cvelistV5/cves/2024/21xxx/CVE-2024-21634.json
func GitHub() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&CPEVersionStringStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

// MITRE returns the strategy pipeline for MITRE advisories.
// Example: test_data/cvelistV5/cves/2021/26xxx/CVE-2021-26917.json,
// test_data/cve5/CVE-2016-1897.json
func MITRE() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

// Linux returns the strategy pipeline for Linux kernel advisories.
// Example: test_data/cvelistV5/cves/2025/21xxx/CVE-2025-21772.json,
// test_data/cvelistV5/cves/2025/21xxx/CVE-2025-21631.json
func Linux() []VersionStrategy {
	return []VersionStrategy{
		&InverseAffectedRangesStrategy{},
		&StandardRangeStrategy{},
		&GitCommitIntroducedOnlyStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

// Curl returns the strategy pipeline for curl advisories.
// Example: test_data/cve5/CVE-2024-7264.json
func Curl() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&CPEVersionStringStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

// Package returns the strategy pipeline for extracting ECOSYSTEM ranges from affected blocks
// that identify a package through a purl. Git ranges are not handled here.
// Example: test_data/cvelistV5/cves/2025/68xxx/CVE-2025-68161.json
func Package() []VersionStrategy {
	return []VersionStrategy{
		&StandardRangeStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}
