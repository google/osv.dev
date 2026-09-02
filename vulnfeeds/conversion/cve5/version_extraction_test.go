package cve5

import (
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/internal/testutils"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
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
			if got := toVersionRangeType(tt.input); got != tt.want {
				t.Errorf("toVersionRangeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindNormalAffectedRanges(t *testing.T) {
	tests := []struct {
		name          string
		affected      models.Affected
		cnaAssigner   string
		wantRanges    []*osvschema.Range
		wantRangeType VersionRangeType
	}{
		{
			name: "simple range",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "1.0",
						LessThan:    "1.5",
						VersionType: "semver",
					},
				},
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("1.0", "", "1.5"),
			},
			wantRangeType: VersionRangeTypeSemver,
		},
		{
			name: "single version fallback",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "2.0",
						VersionType: "semver",
					},
				},
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("2.0", "2.0", ""),
			},
			wantRangeType: VersionRangeTypeSemver,
		},
		{
			name: "mitre single version fallback",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "3.0",
						VersionType: "semver",
					},
				},
			},
			cnaAssigner: "mitre",
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("", "3.0", ""),
			},
			wantRangeType: VersionRangeTypeSemver,
		},
		{
			name: "mitre multiple versions fallback",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "3.0",
						VersionType: "semver",
					},
					{
						Status:      "affected",
						Version:     "3.1",
						VersionType: "semver",
					},
				},
			},
			cnaAssigner: "mitre",
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("3.0", "3.0", ""),
				conversion.BuildVersionRange("3.1", "3.1", ""),
			},
			wantRangeType: VersionRangeTypeSemver,
		},
		{
			name: "github range",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:  "affected",
						Version: ">= 2.0, < 2.5",
					},
				},
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("2.0", "", "2.5"),
			},
			wantRangeType: VersionRangeTypeEcosystem,
		},
		{
			name: "git commit",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "deadbeef",
						VersionType: "git",
					},
				},
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildGitVersionRange("deadbeef", "deadbeef", "", ""),
			},
			wantRangeType: VersionRangeTypeGit,
		},
		{
			name: "changes preferred over lessThanOrEqual with filler version",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:          "affected",
						Version:         "n/a",
						LessThanOrEqual: "1.0.32",
						Changes: []models.Change{
							{At: "1.0.33", Status: "unaffected"},
						},
						VersionType: "custom",
					},
				},
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("0", "", "1.0.33"),
			},
			wantRangeType: VersionRangeTypeEcosystem,
		},
		{
			name: "split range pair (CVE-2022-25929)",
			affected: models.Affected{
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
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("1.31.0", "", "1.36.1"),
			},
			wantRangeType: VersionRangeTypeEcosystem,
		},
		{
			name: "multi split range (CVE-2022-25761)",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "unspecified",
						LessThan:    "1.2.5",
						VersionType: "custom",
					},
					{
						Status:      "affected",
						Version:     "1.3-rc1",
						LessThan:    "unspecified",
						VersionType: "custom",
					},
					{
						Status:      "affected",
						Version:     "unspecified",
						LessThan:    "1.3.1",
						VersionType: "custom",
					},
				},
			},
			wantRanges: []*osvschema.Range{
				conversion.BuildVersionRange("0", "", "1.2.5"),
				conversion.BuildVersionRange("1.3-rc1", "", "1.3.1"),
			},
			wantRangeType: VersionRangeTypeEcosystem,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var versionExtractor VersionExtractor
			if tt.cnaAssigner != "" {
				versionExtractor = GetVersionExtractor(tt.cnaAssigner)
			} else {
				versionExtractor = &DefaultVersionExtractor{}
			}
			gotRangesWithMeta, gotRangeType := versionExtractor.FindNormalAffectedRanges(tt.affected, &models.ConversionMetrics{CNA: tt.cnaAssigner})
			var gotRanges []*osvschema.Range
			for _, r := range gotRangesWithMeta {
				gotRanges = append(gotRanges, r.Range)
			}
			if diff := cmp.Diff(tt.wantRanges, gotRanges, protocmp.Transform()); diff != "" {
				t.Errorf("findNormalAffectedRanges() ranges mismatch (-want +got):\n%s", diff)
			}
			if gotRangeType != tt.wantRangeType {
				t.Errorf("findNormalAffectedRanges() range type = %v, want %v", gotRangeType, tt.wantRangeType)
			}
		})
	}
}

func TestCompareSemverLike(t *testing.T) {
	tests := []struct {
		name string
		a, b string
		want int
	}{
		{"a < b", "1.2.3", "1.2.4", -1},
		{"a > b", "1.3.0", "1.2.4", 1},
		{"a == b", "2.0.0", "2.0.0", 0},
		{"major diff", "3.0.0", "2.0.0", 1},
		{"minor diff", "2.1.0", "2.2.0", -1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := compareSemverLike(tt.a, tt.b); got != tt.want {
				t.Errorf("compareSemverLike() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindInverseAffectedRanges(t *testing.T) {
	tests := []struct {
		name        string
		affected    models.Affected
		versionType VersionRangeType
		cnaAssigner string
		want        []*osvschema.Range
	}{
		{
			name: "linux with wildcard",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "5.0",
						VersionType: "semver",
					},
					{
						Status:          "unaffected",
						Version:         "5.10.1",
						VersionType:     "semver",
						LessThanOrEqual: "5.10.*", // Wildcard, should infer next introduced
					},
				},
			},
			versionType: VersionRangeTypeSemver,
			cnaAssigner: "Linux",
			want: []*osvschema.Range{
				conversion.BuildVersionRange("5.0.0", "", "5.10.1"),
			},
		},
		{
			name: "not linux",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:          "unaffected",
						Version:         "1.0",
						VersionType:     "unknown",
						LessThanOrEqual: "1.0.*",
					},
				},
			},
			versionType: VersionRangeTypeUnknown,
			cnaAssigner: "NotLinux",
			want:        nil,
		},
		{
			name: "linux no wildcard",
			affected: models.Affected{
				Versions: []models.Versions{
					{
						Status:      "affected",
						Version:     "4.0",
						VersionType: "semver",
					},
					{
						Status:          "unaffected",
						Version:         "4.5.2",
						VersionType:     "semver",
						LessThanOrEqual: "4.5.2", // No wildcard
					},
				},
			},
			versionType: VersionRangeTypeSemver,
			cnaAssigner: "Linux",
			want: []*osvschema.Range{
				conversion.BuildVersionRange("4.0.0", "", "4.5.2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := &models.ConversionMetrics{}
			gotRanges, gotVersionType := findInverseAffectedRanges(tt.affected, metrics)
			if diff := cmp.Diff(tt.want, gotRanges, protocmp.Transform()); diff != "" {
				t.Errorf("findInverseAffectedRanges() ranges mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.versionType, gotVersionType); diff != "" {
				t.Errorf("findInverseAffectedRanges() version type mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRealWorldFindInverseAffectedRanges(t *testing.T) {
	testCases := []struct {
		name           string
		cve            models.CVE5
		expectedRanges []*osvschema.Range
	}{
		{
			name: "CVE-2025-21772",
			cve:  loadTestData(t, "CVE-2025-21772"),
			expectedRanges: []*osvschema.Range{
				{Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "5.4.291"}}},
				{Events: []*osvschema.Event{{Introduced: "5.5.0"}, {Fixed: "5.10.235"}}},
				{Events: []*osvschema.Event{{Introduced: "5.11.0"}, {Fixed: "5.15.179"}}},
				{Events: []*osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.129"}}},
				{Events: []*osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.79"}}},
				{Events: []*osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.16"}}},
				{Events: []*osvschema.Event{{Introduced: "6.13.0"}, {Fixed: "6.13.4"}}},
			},
		},
		{
			name: "CVE-2025-21631",
			cve:  loadTestData(t, "CVE-2025-21631"),
			expectedRanges: []*osvschema.Range{
				{Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "5.15.177"}}},
				{Events: []*osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.125"}}},
				{Events: []*osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.72"}}},
				{Events: []*osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.10"}}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var affectedBlock models.Affected
			// Find the specific affected block with defaultStatus: "affected".
			for _, affected := range tc.cve.Containers.CNA.Affected {
				if affected.DefaultStatus == "affected" {
					affectedBlock = affected
					break
				}
			}

			if affectedBlock.Product == "" {
				t.Fatalf("Could not find the 'affected' block with defaultStatus 'affected' in the test file")
			}

			// Run the function under test.
			gotRanges, _ := findInverseAffectedRanges(affectedBlock, &models.ConversionMetrics{})

			// Sort slices for deterministic comparison.
			sort.Slice(gotRanges, func(i, j int) bool {
				if len(gotRanges[i].GetEvents()) == 0 || len(gotRanges[j].GetEvents()) == 0 {
					return false
				}
				eventI := gotRanges[i].GetEvents()[0]
				eventJ := gotRanges[j].GetEvents()[0]
				if eventI.GetIntroduced() != "" && eventJ.GetIntroduced() != "" {
					return eventI.GetIntroduced() < eventJ.GetIntroduced()
				}
				if eventI.GetFixed() != "" && eventJ.GetFixed() != "" {
					return eventI.GetFixed() < eventJ.GetFixed()
				}

				return eventI.GetIntroduced() != ""
			})

			sort.Slice(tc.expectedRanges, func(i, j int) bool {
				if len(tc.expectedRanges[i].GetEvents()) == 0 || len(tc.expectedRanges[j].GetEvents()) == 0 {
					return false
				}
				eventI := tc.expectedRanges[i].GetEvents()[0]
				eventJ := tc.expectedRanges[j].GetEvents()[0]
				if eventI.GetIntroduced() != "" && eventJ.GetIntroduced() != "" {
					return eventI.GetIntroduced() < eventJ.GetIntroduced()
				}
				if eventI.GetFixed() != "" && eventJ.GetFixed() != "" {
					return eventI.GetFixed() < eventJ.GetFixed()
				}

				return eventI.GetIntroduced() != ""
			})

			if diff := cmp.Diff(tc.expectedRanges, gotRanges, protocmp.Transform()); diff != "" {
				t.Errorf("findInverseAffectedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestGetVersionExtractor(t *testing.T) {
	testCases := []struct {
		name         string
		cve          models.CVE5
		expectedType reflect.Type
	}{
		{
			name: "Linux CVE",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					AssignerShortName: "Linux",
				},
			},
			expectedType: reflect.TypeOf(&LinuxVersionExtractor{}),
		},
		{
			name: "Default CVE",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					AssignerShortName: "Anything",
				},
			},
			expectedType: reflect.TypeOf(&DefaultVersionExtractor{}),
		},
		{
			name:         "Empty provider",
			cve:          models.CVE5{},
			expectedType: reflect.TypeOf(&DefaultVersionExtractor{}),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			extractor := GetVersionExtractor(tc.cve.Metadata.AssignerShortName)
			if reflect.TypeOf(extractor) != tc.expectedType {
				t.Errorf("GetVersionExtractor() returned type %v, want %v", reflect.TypeOf(extractor), tc.expectedType)
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
		vers := models.Versions{
			Status:      "affected",
			Version:     "1.0.0",
			LessThan:    "1.5.0",
			VersionType: "semver",
		}
		ranges, vrt, handled := strategy.Extract(vers, models.Affected{}, metrics)
		if !handled || vrt != VersionRangeTypeSemver || len(ranges) != 1 {
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
		vers := models.Versions{
			Status:      "affected",
			Version:     "1.0.0",
			VersionType: "semver",
			Changes: []models.Change{
				{Status: "unaffected", At: "1.0.1"},
			},
		}
		ranges, vrt, handled := strategy.Extract(vers, models.Affected{}, metrics)
		if !handled || vrt != VersionRangeTypeSemver || len(ranges) != 1 {
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
		vers := models.Versions{
			Status:      "affected",
			Version:     ">= 1.2.0, < 2.0.0",
			VersionType: "semver",
		}
		ranges, vrt, handled := strategy.Extract(vers, models.Affected{}, metrics)
		if !handled || vrt != VersionRangeTypeSemver || len(ranges) != 1 {
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
		vers := models.Versions{
			Status:      "affected",
			Version:     "2.52",
			VersionType: "custom",
		}
		ranges, vrt, handled := strategy.Extract(vers, models.Affected{}, metrics)
		if !handled || vrt != VersionRangeTypeEcosystem || len(ranges) != 1 {
			t.Fatalf("ZeroIntroducedSingleVersionStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "0" || events[1].GetLastAffected() != "2.52" {
			t.Errorf("unexpected events: %+v", events)
		}

		// Should not handle if multiple versions are listed
		multiAffected := models.Affected{
			Versions: []models.Versions{
				{Status: "affected", Version: "3.0.0"},
				{Status: "affected", Version: "3.1.0"},
			},
		}
		_, _, handledMulti := strategy.Extract(multiAffected.Versions[0], multiAffected, metrics)
		if handledMulti {
			t.Errorf("ZeroIntroducedSingleVersionStrategy should not handle multiple versions")
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

		ranges1, _, handled1 := strategy.Extract(affectedSplit.Versions[0], affectedSplit, metrics)
		if !handled1 || len(ranges1) != 1 {
			t.Fatalf("SplitRangeStrategy failed to extract first split entry: %+v", ranges1)
		}
		events1 := ranges1[0].Range.GetEvents()
		if events1[0].GetIntroduced() != "1.31.0" || events1[1].GetFixed() != "1.36.1" {
			t.Errorf("unexpected events from first split entry: %+v", events1)
		}

		ranges2, _, handled2 := strategy.Extract(affectedSplit.Versions[1], affectedSplit, metrics)
		if !handled2 || len(ranges2) != 0 {
			t.Errorf("expected second split entry to be consumed, got: %+v", ranges2)
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
		rangesUpper, _, handledUpper := strategy.Extract(affectedUpper.Versions[0], affectedUpper, metrics)
		if !handledUpper || len(rangesUpper) != 1 {
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
		vers := models.Versions{
			Status:      "affected",
			Version:     "0b3b5fdb5a058f50248cd8547824936b8dd10351",
			VersionType: "git",
		}
		affected := models.Affected{
			Repo: "https://github.com/GeneralSandman/TinyWeb",
		}
		ranges, vrt, handled := strategy.Extract(vers, affected, metrics)
		if !handled || vrt != VersionRangeTypeGit || len(ranges) != 1 {
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
		vers := models.Versions{
			Status:      "affected",
			Version:     "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2",
			VersionType: "git",
		}
		affected := models.Affected{
			Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
		}
		ranges, vrt, handled := strategy.Extract(vers, affected, metrics)
		if !handled || vrt != VersionRangeTypeGit || len(ranges) != 1 {
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
		vers := models.Versions{
			Status:      "affected",
			Version:     "1.0.0",
			VersionType: "semver",
		}
		ranges, vrt, handled := strategy.Extract(vers, models.Affected{}, metrics)
		if !handled || vrt != VersionRangeTypeSemver || len(ranges) != 1 {
			t.Fatalf("StandaloneSingleVersionStrategy failed to extract range")
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.0.0" || events[1].GetLastAffected() != "1.0.0" {
			t.Errorf("unexpected events: %+v", events)
		}
	})

	t.Run("StrategyPrioritySorting", func(t *testing.T) {
		t.Parallel()
		extractor := &DefaultVersionExtractor{
			Strategies: []VersionStrategy{
				&StandaloneSingleVersionStrategy{}, // PriorityLastResort (300)
				&StandardRangeStrategy{},           // PriorityStandard (200)
				&ChangesAtStrategy{},               // PriorityFirst (100)
			},
		}
		sorted := extractor.getStrategies()
		if len(sorted) != 3 {
			t.Fatalf("expected 3 strategies, got %d", len(sorted))
		}
		if sorted[0].Name() != "ChangesAt" || sorted[0].Priority() != PriorityFirst {
			t.Errorf("expected first strategy to be ChangesAt, got %s", sorted[0].Name())
		}
		if sorted[1].Name() != "StandardRange" || sorted[1].Priority() != PriorityStandard {
			t.Errorf("expected second strategy to be StandardRange, got %s", sorted[1].Name())
		}
		if sorted[2].Name() != "StandaloneSingleVersion" || sorted[2].Priority() != PriorityLastResort {
			t.Errorf("expected third strategy to be StandaloneSingleVersion, got %s", sorted[2].Name())
		}

		boosted := WithPriority(&StandaloneSingleVersionStrategy{}, PriorityFirst-10)
		if boosted.Priority() >= PriorityFirst {
			t.Errorf("expected boosted priority to be lower than PriorityFirst")
		}
	})

	t.Run("AffectedCPEStrategy", func(t *testing.T) {
		t.Parallel()
		metrics := &models.ConversionMetrics{}
		strategy := &AffectedCPEStrategy{}
		affected := models.Affected{
			Cpes: []string{"cpe:2.3:a:vendor:product:1.2.3:*:*:*:*:*:*:*"},
		}
		vers := models.Versions{
			Status: "affected",
		}
		ranges, _, handled := strategy.Extract(vers, affected, metrics)
		if !handled || len(ranges) != 1 {
			t.Fatalf("AffectedCPEStrategy failed to extract range")
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
		ranges, err := strategy.Extract(cve, metrics)
		if err != nil || len(ranges) != 1 {
			t.Fatalf("CPEVersionStrategy failed to extract range: %v", err)
		}
		events := ranges[0].Range.GetEvents()
		if events[0].GetIntroduced() != "1.0.0" || events[1].GetFixed() != "2.0.0" {
			t.Errorf("unexpected events: %+v", events)
		}
	})
}

func TestExtractVersions(t *testing.T) {
	testCases := []struct {
		name             string
		cve              models.CVE5
		cnaAssigner      string
		repos            []string
		expectedAffected []*osvschema.Affected
	}{
		{
			name:  "CVE-2023-45803",
			cve:   loadTestData(t, "CVE-2023-45803"),
			repos: []string{"https://github.com/urllib3/urllib3"},
			expectedAffected: []*osvschema.Affected{{
				Ranges: []*osvschema.Range{{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/urllib3/urllib3",
					Events: []*osvschema.Event{
						{Introduced: "6446fef0cf432ca035169602a1447a0d8ef53e80"},
						{Fixed: "56f01e088dc006c03d4ee6ea9da4ab810f1ed700"},
						{Introduced: "0"},
						{Fixed: "9c2c2307dd1d6af504e09aac0326d86ee3597a0b"},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": structpb.NewStringValue("AFFECTED_FIELD"),
							"extracted_events": {
								Kind: &structpb.Value_ListValue{
									ListValue: &structpb.ListValue{
										Values: []*structpb.Value{
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"introduced": structpb.NewStringValue("2.0.0"),
														},
													},
												},
											},
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"fixed": structpb.NewStringValue("2.0.7"),
														},
													},
												},
											},
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"introduced": structpb.NewStringValue("0"),
														},
													},
												},
											},
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"fixed": structpb.NewStringValue("1.26.18"),
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
		{
			name:  "CVE-2024-21634",
			cve:   loadTestData(t, "CVE-2024-21634"),
			repos: []string{"https://github.com/amazon-ion/ion-java"},
			expectedAffected: []*osvschema.Affected{{
				Ranges: []*osvschema.Range{{
					Type: osvschema.Range_GIT,
					Repo: "https://github.com/amazon-ion/ion-java",
					Events: []*osvschema.Event{
						{Introduced: "0"},
						{Fixed: "019a6117fb99131f74f92ecf462169613234abbf"},
					},
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"source": structpb.NewStringValue("AFFECTED_FIELD"),
							"extracted_events": {
								Kind: &structpb.Value_ListValue{
									ListValue: &structpb.ListValue{
										Values: []*structpb.Value{
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"introduced": structpb.NewStringValue("0"),
														},
													},
												},
											},
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"fixed": structpb.NewStringValue("1.10.5"),
														},
													},
												},
											},
										},
									},
								},
							},
						},
					},
				}},
			}},
		},
		{
			name:        "CVE-2025-21772",
			cve:         loadTestData(t, "CVE-2025-21772"),
			cnaAssigner: "Linux",
			repos: []string{
				"https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
			},
			expectedAffected: []*osvschema.Affected{{
				Ranges: []*osvschema.Range{{
					Type: osvschema.Range_GIT,
					Events: []*osvschema.Event{
						{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
						{Fixed: "a3e77da9f843e4ab93917d30c314f0283e28c124"},
					},
					Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
				},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "92527100be38ede924768f4277450dfe8a40e16b"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "6578717ebca91678131d2b1f4ba4258e60536e9f"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "7fa9706722882f634090bfc9af642bf9ed719e27"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: osvschema.Range_GIT,
						Events: []*osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "80e648042e512d5a767da251d44132553fe04ae0"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					}},
			},
				{
					Package: &osvschema.Package{Ecosystem: "Linux", Name: "Kernel"},
					Ranges: []*osvschema.Range{
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "5.4.291"}}},
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "5.5.0"}, {Fixed: "5.10.235"}}},
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "5.11.0"}, {Fixed: "5.15.179"}}},
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.129"}}},
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.79"}}},
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.16"}}},
						{Type: osvschema.Range_ECOSYSTEM, Events: []*osvschema.Event{{Introduced: "6.13.0"}, {Fixed: "6.13.4"}}},
					},
				}},
		},
		{
			name:        "CVE-2026-67185",
			cve:         loadTestCVE(t, filepath.Join("..", "..", "cmd", "converters", "cve", "cve5", "bulk-converter", "cvelistV5", "cves", "2026", "67xxx", "CVE-2026-67185.json")),
			cnaAssigner: "VulnCheck",
			repos:       []string{"https://github.com/GeneralSandman/TinyWeb"},
			expectedAffected: []*osvschema.Affected{{
				Ranges: []*osvschema.Range{{
					Repo: "https://github.com/GeneralSandman/TinyWeb",
					Type: osvschema.Range_GIT,
					Events: []*osvschema.Event{
						{Introduced: "0b3b5fdb5a058f50248cd8547824936b8dd10351"},
						{LastAffected: "a381da252fe8e873c8aff22703040426cc9b2ae0"},
					},
				}},
			}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			r := testutils.SetupGitVCR(t)
			metrics := &models.ConversionMetrics{}
			v := vulns.Vulnerability{
				Vulnerability: &osvschema.Vulnerability{},
			}
			extractor := GetVersionExtractor(tc.cnaAssigner)
			cache := &git.InMemoryRepoTagsCache{}
			extractor.ExtractVersions(tc.cve, &v, metrics, tc.repos, cache, r.GetDefaultClient())

			if diff := cmp.Diff(tc.expectedAffected, v.Affected, protocmp.Transform()); diff != "" {
				t.Errorf("ExtractVersions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtractVersions_NoReposEarlyExit(t *testing.T) {
	cve := models.CVE5{
		Metadata: models.CVE5Metadata{
			CVEID:             "CVE-2026-0001",
			AssignerShortName: "mitre",
		},
		Containers: struct {
			CNA models.CNA   `json:"cna"`
			ADP []models.CNA `json:"adp,omitempty"`
		}{
			CNA: models.CNA{
				Affected: []models.Affected{
					{
						Vendor:  "Vendor",
						Product: "Product",
						Versions: []models.Versions{
							{
								Status:   "affected",
								Version:  "1.0.0",
								LessThan: "1.2.0",
							},
						},
					},
				},
				Descriptions: []models.LangString{
					{
						Lang:  "en",
						Value: "Vulnerability in Product before 1.2.0 allows attackers to execute code.",
					},
				},
			},
		},
	}

	metrics := &models.ConversionMetrics{CVEID: "CVE-2026-0001", CNA: "mitre"}
	v := vulns.Vulnerability{
		Vulnerability: &osvschema.Vulnerability{
			Id: "CVE-2026-0001",
		},
	}

	extractor := GetVersionExtractor("mitre")
	r := testutils.SetupGitVCR(t)
	cache := &git.InMemoryRepoTagsCache{}
	extractor.ExtractVersions(cve, &v, metrics, []string{}, cache, r.GetDefaultClient())

	if metrics.Outcome != models.NoRepos {
		t.Errorf("expected outcome to be NoRepos, got %v", metrics.Outcome)
	}

	// Should not have attempted fallback to description
	for _, note := range metrics.Notes {
		if strings.Contains(note, "attempting extraction from description") || strings.Contains(note, "attempting to extract from CPE") {
			t.Errorf("unexpected fallback note present when repos is empty: %s", note)
		}
	}

	if v.DatabaseSpecific == nil {
		t.Fatalf("expected DatabaseSpecific to be populated with unresolved_ranges")
	}

	fields := v.DatabaseSpecific.GetFields()
	if _, ok := fields["unresolved_ranges"]; !ok {
		t.Errorf("expected unresolved_ranges in DatabaseSpecific")
	}
}
