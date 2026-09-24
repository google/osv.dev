package strategies

// Strategy Pipeline Presets for different CNAs

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
		&InverseAffectedRangesStrategy{},
	}
}

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

func WPScan() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func Wordfence() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func Patchstack() []VersionStrategy {
	return []VersionStrategy{
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&CPEVersionStringStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}

func MITRE() []VersionStrategy {
	return []VersionStrategy{
		&SplitRangeStrategy{},
		&ChangesAtStrategy{},
		&StandardRangeStrategy{},
		&StringRangeExpressionStrategy{},
		&GitCommitStrategy{},
		&CPEVersionStringStrategy{},
		&VersionTextExtractionStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
		&StandaloneSingleVersionStrategy{},
		&InverseAffectedRangesStrategy{},
	}
}

func Linux() []VersionStrategy {
	return []VersionStrategy{
		&InverseAffectedRangesStrategy{},
		&StandardRangeStrategy{},
		&GitCommitIntroducedOnlyStrategy{},
		&ZeroIntroducedSingleVersionStrategy{},
	}
}
