package strategies

// Strategy Pipeline Presets for different CNAs

func Default() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&AffectedCPEStrategy{},
		&VersionTextExtractionStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

func DefaultStrategies() []VersionStrategy {
	return Default()
}

func GitHub() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&AffectedCPEStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

func GitHubStrategies() []VersionStrategy {
	return GitHub()
}

func WPScan() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func WPScanStrategies() []VersionStrategy {
	return WPScan()
}

func Wordfence() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func WordfenceStrategies() []VersionStrategy {
	return Wordfence()
}

func Patchstack() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func PatchstackStrategies() []VersionStrategy {
	return Patchstack()
}

func MITRE() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&AffectedCPEStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
		&StandaloneSingleVersionStrategy{},
	}
}

func MITREStrategies() []VersionStrategy {
	return MITRE()
}

func Linux() []VersionStrategy {
	return []VersionStrategy{
		&StandardRangeStrategy{},
		&GitCommitIntroducedOnlyStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func LinuxStrategies() []VersionStrategy {
	return Linux()
}
