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
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&CPEVersionStringStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

// WPScan returns the strategy pipeline for WPScan advisories.
// Example: test_data/cvelistV5/cves/2015/10xxx/CVE-2015-10001.json
func WPScan() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

// Wordfence returns the strategy pipeline for Wordfence advisories.
// Example: test_data/cvelistV5/cves/2026/1xxx/CVE-2026-1293.json
func Wordfence() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

// Patchstack returns the strategy pipeline for Patchstack advisories.
// Example: test_data/cvelistV5/cves/2021/23xxx/CVE-2021-23209.json
func Patchstack() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

// MITRE returns the strategy pipeline for MITRE advisories.
// Example: test_data/cvelistV5/cves/2021/26xxx/CVE-2021-26917.json,
// test_data/cve5/CVE-2016-1897.json
func MITRE() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
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
