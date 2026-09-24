package cve5

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5/strategies"
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
		want  strategies.VersionRangeType
	}{
		{"git", "git", strategies.VersionRangeTypeGit},
		{"semver", "semver", strategies.VersionRangeTypeSemver},
		{"ecosystem", "ecosystem", strategies.VersionRangeTypeEcosystem},
		{"other", "custom", strategies.VersionRangeTypeEcosystem},
		{"empty", "", strategies.VersionRangeTypeEcosystem},
		{"case insensitive", "GiT", strategies.VersionRangeTypeGit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := strategies.ToVersionRangeType(tt.input); got != tt.want {
				t.Errorf("ToVersionRangeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindNormalAffectedRanges(t *testing.T) {
	tests := []struct {
		name        string
		affected    models.Affected
		cnaAssigner string
		wantRanges  []*osvschema.Range
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
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var strategyList []strategies.VersionStrategy
			switch strings.ToLower(tt.cnaAssigner) {
			case "linux":
				strategyList = strategies.Linux()
			case "github_m", "github":
				strategyList = strategies.GitHub()
			case "mitre":
				strategyList = strategies.MITRE()
			default:
				strategyList = strategies.Default()
			}
			gotRangesWithMeta := ExtractAffectedRanges(tt.affected, strategyList, &models.ConversionMetrics{CNA: tt.cnaAssigner})
			var gotRanges []*osvschema.Range
			for _, r := range gotRangesWithMeta {
				gotRanges = append(gotRanges, r.Range)
			}
			if diff := cmp.Diff(tt.wantRanges, gotRanges, protocmp.Transform()); diff != "" {
				t.Errorf("ExtractAffectedRanges() ranges mismatch (-want +got):\n%s", diff)
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
			if got := strategies.CompareSemverLike(tt.a, tt.b); got != tt.want {
				t.Errorf("CompareSemverLike() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFindInverseAffectedRanges(t *testing.T) {
	tests := []struct {
		name        string
		affected    models.Affected
		versionType strategies.VersionRangeType
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
			versionType: strategies.VersionRangeTypeSemver,
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
			versionType: strategies.VersionRangeTypeUnknown,
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
			versionType: strategies.VersionRangeTypeSemver,
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
			expectedType: reflect.TypeFor[*LinuxVersionExtractor](),
		},
		{
			name: "Default CVE",
			cve: models.CVE5{
				Metadata: models.CVE5Metadata{
					AssignerShortName: "Anything",
				},
			},
			expectedType: reflect.TypeFor[*DefaultVersionExtractor](),
		},
		{
			name:         "Empty provider",
			cve:          models.CVE5{},
			expectedType: reflect.TypeFor[*DefaultVersionExtractor](),
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

func TestDefaultVersionExtractor_SliceOrderPrecedence(t *testing.T) {
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

	// When StandardRangeStrategy is first in slice order:
	pipeline1 := []strategies.VersionStrategy{
		&strategies.StandardRangeStrategy{},
		&strategies.StandaloneSingleVersionStrategy{},
	}
	ranges1 := ExtractAffectedRanges(affected, pipeline1, &models.ConversionMetrics{})
	if len(ranges1) != 1 || ranges1[0].Range.GetEvents()[1].GetFixed() != "1.5.0" {
		t.Fatalf("expected StandardRangeStrategy to match first, got: %+v", ranges1)
	}

	// When StandaloneSingleVersionStrategy is first in slice order:
	pipeline2 := []strategies.VersionStrategy{
		&strategies.StandaloneSingleVersionStrategy{},
		&strategies.StandardRangeStrategy{},
	}
	ranges2 := ExtractAffectedRanges(affected, pipeline2, &models.ConversionMetrics{})
	if len(ranges2) != 1 || ranges2[0].Range.GetEvents()[1].GetLastAffected() != "1.0.0" {
		t.Fatalf("expected StandaloneSingleVersionStrategy to match first when placed earlier, got: %+v", ranges2)
	}
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
							"extracted_events": {
								Kind: &structpb.Value_ListValue{
									ListValue: &structpb.ListValue{
										Values: []*structpb.Value{
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"source":   structpb.NewStringValue("AFFECTED_FIELD"),
															"strategy": structpb.NewStringValue("StringRangeExpression"),
															"range": {
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
																		},
																	},
																},
															},
														},
													},
												},
											},
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"source":   structpb.NewStringValue("AFFECTED_FIELD"),
															"strategy": structpb.NewStringValue("StringRangeExpression"),
															"range": {
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
							"extracted_events": {
								Kind: &structpb.Value_ListValue{
									ListValue: &structpb.ListValue{
										Values: []*structpb.Value{
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"source":   structpb.NewStringValue("AFFECTED_FIELD"),
															"strategy": structpb.NewStringValue("StringRangeExpression"),
															"range": {
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
			cve:         loadTestData(t, "CVE-2026-67185"),
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
					DatabaseSpecific: &structpb.Struct{
						Fields: map[string]*structpb.Value{
							"extracted_events": {
								Kind: &structpb.Value_ListValue{
									ListValue: &structpb.ListValue{
										Values: []*structpb.Value{
											{
												Kind: &structpb.Value_StructValue{
													StructValue: &structpb.Struct{
														Fields: map[string]*structpb.Value{
															"source":   structpb.NewStringValue("AFFECTED_FIELD"),
															"strategy": structpb.NewStringValue("StandardRange"),
															"range": {
																Kind: &structpb.Value_ListValue{
																	ListValue: &structpb.ListValue{
																		Values: []*structpb.Value{
																			{
																				Kind: &structpb.Value_StructValue{
																					StructValue: &structpb.Struct{
																						Fields: map[string]*structpb.Value{
																							"introduced": structpb.NewStringValue("0b3b5fdb5a058f50248cd8547824936b8dd10351"),
																						},
																					},
																				},
																			},
																			{
																				Kind: &structpb.Value_StructValue{
																					StructValue: &structpb.Struct{
																						Fields: map[string]*structpb.Value{
																							"last_affected": structpb.NewStringValue("a381da252fe8e873c8aff22703040426cc9b2ae0"),
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
