package strategies

import (
	"testing"

	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func TestToVersionRangeType(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  VersionRangeType
	}{
		{"git", "git", VersionRangeTypeGit},
		{"semver", "semver", VersionRangeTypeSemver},
		{"ecosystem", "ecosystem", VersionRangeTypeEcosystem},
		{"other", "custom", VersionRangeTypeEcosystem},
		{"empty", "", VersionRangeTypeEcosystem},
		{"case insensitive", "GiT", VersionRangeTypeGit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ToVersionRangeType(tt.input); got != tt.want {
				t.Errorf("ToVersionRangeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestStrategies(t *testing.T) {
	t.Parallel()

	t.Run("StandardRangeStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &StandardRangeStrategy{}
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "1.0.0",
					LessThan:    "1.5.0",
					VersionType: "semver",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("StandardRangeStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.0.0" || events[1].GetFixed() != "1.5.0" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("ChangesAtStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &ChangesAtStrategy{}
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "1.0.0",
					VersionType: "semver",
					Changes: []models.Change{
						{Status: "unaffected", At: "1.0.1"},
					},
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("ChangesAtStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.0.0" || events[1].GetFixed() != "1.0.1" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("StringRangeExpressionStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &StringRangeExpressionStrategy{}
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     ">= 1.2.0, < 2.0.0",
					VersionType: "semver",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("StringRangeExpressionStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.2.0" || events[1].GetFixed() != "2.0.0" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("ZeroIntroducedSingleVersionStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &ZeroIntroducedSingleVersionStrategy{}
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "2.52",
					VersionType: "custom",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("ZeroIntroducedSingleVersionStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "0" || events[1].GetLastAffected() != "2.52" {
			t.Errorf("unexpected events: %+v", events)
		}

		// Should not handle if multiple versions were originally listed in affected.Versions,
		// even if only 1 unhandled version remains!
		multiAffected := models.Affected{
			Versions: []models.Versions{
				{Status: "affected", Version: "1.0.0", LessThan: "1.5.0"},
				{Status: "affected", Version: "2.0.0"},
			},
		}
		multiState := NewExtractionState(multiAffected)
		(&StandardRangeStrategy{}).Extract(multiState, metrics)
		prevCount := len(multiState.Ranges())
		strategy.Extract(multiState, metrics)
		if len(multiState.Ranges()) != prevCount || multiState.IsConsumed(1) {
			t.Errorf("ZeroIntroducedSingleVersionStrategy should not handle partially consumed multi-version block")
		}
	})

	t.Run("SplitRangeStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &SplitRangeStrategy{}

		// 1. Split unspecified pair (e.g., CVE-2022-25929)
		affectedSplit := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "1.31.0",
					LessThan:    "unspecified",
					VersionType: "custom",
				},
				{
					Status:      "affected",
					Version:     "unspecified",
					LessThan:    "1.36.1",
					VersionType: "custom",
				},
			},
		}

		stateSplit := NewExtractionState(affectedSplit)
		strategy.Extract(stateSplit, metrics)
		rangesSplit := stateSplit.Ranges()
		if !stateSplit.AllConsumed() || len(rangesSplit) != 1 {
			t.Fatalf("SplitRangeStrategy failed to extract split pair: %+v", rangesSplit)
		}
		events1 := rangesSplit[0].Range.GetEvents()
		if events1[0].GetIntroduced() != "1.31.0" || events1[1].GetFixed() != "1.36.1" {
			t.Errorf("unexpected events from split pair: %+v", events1)
		}

		// 2. Standalone upper bound (e.g., CVE-2022-25865)
		affectedUpper := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "unspecified",
					LessThan:    "0.18.4",
					VersionType: "custom",
				},
			},
		}
		stateUpper := NewExtractionState(affectedUpper)
		strategy.Extract(stateUpper, metrics)
		rangesUpper := stateUpper.Ranges()
		if !stateUpper.AllConsumed() || len(rangesUpper) != 1 {
			t.Fatalf("SplitRangeStrategy failed to extract standalone upper bound: %+v", rangesUpper)
		}
		eventsUpper := rangesUpper[0].Range.GetEvents()
		if eventsUpper[0].GetIntroduced() != "0" || eventsUpper[1].GetFixed() != "0.18.4" {
			t.Errorf("unexpected events from standalone upper bound: %+v", eventsUpper)
		}
	})

	t.Run("GitCommitStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &GitCommitStrategy{}
		affected := models.Affected{
			Repo: "https://github.com/GeneralSandman/TinyWeb",
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "0b3b5fdb5a058f50248cd8547824936b8dd10351",
					VersionType: "git",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("GitCommitStrategy failed to extract range")
		}
		if ranges[0].Range.GetType() != osvschema.Range_GIT || ranges[0].Range.GetRepo() != "https://github.com/GeneralSandman/TinyWeb" {
			t.Errorf("unexpected range properties: %+v", ranges[0].Range)
		}
	})

	t.Run("GitCommitIntroducedOnlyStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &GitCommitIntroducedOnlyStrategy{}
		affected := models.Affected{
			Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2",
					VersionType: "git",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("GitCommitIntroducedOnlyStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if len(events) != 1 || events[0].GetIntroduced() != "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("StandaloneSingleVersionStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &StandaloneSingleVersionStrategy{}
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "1.0.0",
					VersionType: "semver",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("StandaloneSingleVersionStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.0.0" || events[1].GetLastAffected() != "1.0.0" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("PipelineOrderPrecedence", func(t *testing.T) {
		t.Parallel()
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:      "affected",
					Version:     "1.0.0",
					LessThan:    "1.5.0",
					VersionType: "semver",
				},
			},
		}

		// When StandardRangeStrategy comes first:
		pipeline1 := []VersionStrategy{
			&StandardRangeStrategy{},
			&StandaloneSingleVersionStrategy{},
		}
		state1 := NewExtractionState(affected)
		for _, s := range pipeline1 {
			if state1.AllConsumed() {
				break
			}
			s.Extract(state1, &models.ConversionMetrics{})
		}
		ranges1 := state1.Ranges()
		if len(ranges1) != 1 || ranges1[0].Range.GetEvents()[1].GetFixed() != "1.5.0" {
			t.Fatalf("expected StandardRangeStrategy to handle first, got: %+v", ranges1)
		}

		// When StandaloneSingleVersionStrategy comes first:
		pipeline2 := []VersionStrategy{
			&StandaloneSingleVersionStrategy{},
			&StandardRangeStrategy{},
		}
		state2 := NewExtractionState(affected)
		for _, s := range pipeline2 {
			if state2.AllConsumed() {
				break
			}
			s.Extract(state2, &models.ConversionMetrics{})
		}
		ranges2 := state2.Ranges()
		if len(ranges2) != 1 || ranges2[0].Range.GetEvents()[1].GetLastAffected() != "1.0.0" {
			t.Fatalf("expected StandaloneSingleVersionStrategy to handle first when placed earlier, got: %+v", ranges2)
		}
	})

	t.Run("CPEVersionStringStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &CPEVersionStringStrategy{}
		affected := models.Affected{
			Versions: []models.Versions{
				{
					Status:  "affected",
					Version: "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*",
				},
			},
		}
		state := NewExtractionState(affected)
		strategy.Extract(state, metrics)
		ranges := state.Ranges()
		if !state.AllConsumed() || len(ranges) != 1 {
			t.Fatalf("CPEVersionStringStrategy expected 1 range and all consumed, got %d ranges", len(ranges))
		}
		if ranges[0].Metadata.CPE != "cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*" {
			t.Errorf("unexpected CPE metadata: %s", ranges[0].Metadata.CPE)
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.2.3" || events[1].GetLastAffected() != "1.2.3" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("CPEVersionStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &CPEVersionStrategy{}
		cve := models.CVE5{}
		cve.Containers.CNA.CPEApplicability = []models.CPE{
			{
				Nodes: []models.CPENode{
					{
						Operator: "OR",
						CPEMatch: []struct {
							Vulnerable            bool   `json:"vulnerable,omitempty"`
							Criteria              string `json:"criteria,omitempty"`
							VersionEndIncluding   string `json:"versionEndIncluding,omitempty"`
							VersionStartExcluding string `json:"versionStartExcluding,omitempty" mapstructure:"versionStartExcluding,omitempty" yaml:"versionStartExcluding,omitempty"`
							VersionStartIncluding string `json:"versionStartIncluding,omitempty" mapstructure:"versionStartIncluding,omitempty" yaml:"versionStartIncluding,omitempty"`
							VersionEndExcluding   string `json:"versionEndExcluding,omitempty"`
						}{
							{
								Vulnerable:            true,
								Criteria:              "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*",
								VersionStartIncluding: "1.0.0",
								VersionEndExcluding:   "2.0.0",
							},
						},
					},
				},
			},
		}
		// Also include affected.Cpes to verify both cpeApplicability and affected.Cpes are extracted without duplicates
		cve.Containers.CNA.Affected = []models.Affected{
			{
				Cpes: []string{"cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"},
			},
		}
		ranges, err := strategy.Extract(cve, metrics)
		if err != nil || len(ranges) != 2 {
			t.Fatalf("CPEVersionStrategy failed to extract ranges: %v (got %d ranges)", err, len(ranges))
		}
		events0 := ranges[0].Range.GetEvents()
		if events0[0].GetIntroduced() != "1.0.0" || events0[1].GetFixed() != "2.0.0" {
			t.Errorf("unexpected events[0]: %+v", events0)
		}
		events1 := ranges[1].Range.GetEvents()
		if events1[0].GetIntroduced() != "1.2.3" || events1[1].GetLastAffected() != "1.2.3" {
			t.Errorf("unexpected events[1]: %+v", events1)
		}
	})
}
