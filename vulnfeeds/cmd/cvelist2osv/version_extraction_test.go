package cvelist2osv

import (
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
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
			if got := toVersionRangeType(tt.input); got != tt.want {
				t.Errorf("toVersionRangeType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuildVersionRange(t *testing.T) {
	tests := []struct {
		name    string
		intro   string
		lastAff string
		fixed   string
		want    osvschema.Range
	}{
		{
			name:  "intro and fixed",
			intro: "1.0.0",
			fixed: "1.0.1",
			want: osvschema.Range{
				Events: []osvschema.Event{
					{Introduced: "1.0.0"},
					{Fixed: "1.0.1"},
				},
			},
		},
		{
			name:    "intro and last_affected",
			intro:   "1.0.0",
			lastAff: "1.0.0",
			want: osvschema.Range{
				Events: []osvschema.Event{
					{Introduced: "1.0.0"},
					{LastAffected: "1.0.0"},
				},
			},
		},
		{
			name:  "only intro",
			intro: "1.0.0",
			want: osvschema.Range{
				Events: []osvschema.Event{
					{Introduced: "1.0.0"},
				},
			},
		},
		{
			name: "empty intro",
			want: osvschema.Range{
				Events: []osvschema.Event{
					{Introduced: "0"},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildVersionRange(tt.intro, tt.lastAff, tt.fixed)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("buildVersionRange() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestFindNormalAffectedRanges(t *testing.T) {
	tests := []struct {
		name          string
		affected      cves.Affected
		cnaAssigner   string
		wantRanges    []osvschema.Range
		wantRangeType VersionRangeType
	}{
		{
			name: "simple range",
			affected: cves.Affected{
				Versions: []cves.Versions{
					{
						Status:      "affected",
						Version:     "1.0",
						LessThan:    "1.5",
						VersionType: "semver",
					},
				},
			},
			wantRanges: []osvschema.Range{
				buildVersionRange("1.0", "", "1.5"),
			},
			wantRangeType: VersionRangeTypeSemver,
		},
		{
			name: "single version fallback",
			affected: cves.Affected{
				Versions: []cves.Versions{
					{
						Status:      "affected",
						Version:     "2.0",
						VersionType: "semver",
					},
				},
			},
			wantRanges: []osvschema.Range{
				buildVersionRange("0", "", "2.0"),
			},
			wantRangeType: VersionRangeTypeSemver,
		},
		{
			name: "github range",
			affected: cves.Affected{
				Versions: []cves.Versions{
					{
						Status:  "affected",
						Version: ">= 2.0, < 2.5",
					},
				},
			},
			wantRanges: []osvschema.Range{
				buildVersionRange("2.0", "", "2.5"),
			},
			wantRangeType: VersionRangeTypeEcosystem,
		},
		{
			name: "git commit",
			affected: cves.Affected{
				Versions: []cves.Versions{
					{
						Status:      "affected",
						Version:     "deadbeef",
						VersionType: "git",
					},
				},
			},
			wantRanges: []osvschema.Range{
				buildVersionRange("deadbeef", "", ""),
			},
			wantRangeType: VersionRangeTypeGit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRanges, gotRangeType, _ := findNormalAffectedRanges(tt.affected)
			if diff := cmp.Diff(tt.wantRanges, gotRanges); diff != "" {
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
		affected    cves.Affected
		versionType VersionRangeType
		cnaAssigner string
		want        []osvschema.Range
	}{
		{
			name: "linux with wildcard",
			affected: cves.Affected{
				Versions: []cves.Versions{
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
			want: []osvschema.Range{
				buildVersionRange("5.0.0", "", "5.10.1"),
			},
		},
		{
			name: "not linux",
			affected: cves.Affected{
				Versions: []cves.Versions{
					{
						Status:          "unaffected",
						Version:         "1.0",
						VersionType:     "semver",
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
			affected: cves.Affected{
				Versions: []cves.Versions{
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
			want: []osvschema.Range{
				buildVersionRange("4.0.0", "", "4.5.2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotRanges, gotVersionType, _ := findInverseAffectedRanges(tt.affected, tt.cnaAssigner)
			if diff := cmp.Diff(tt.want, gotRanges); diff != "" {
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
		cve            cves.CVE5
		expectedRanges []osvschema.Range
	}{
		{
			name: "CVE-2025-21772",
			cve:  loadTestData(t, "CVE-2025-21772"),
			expectedRanges: []osvschema.Range{
				{Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.4.291"}}},
				{Events: []osvschema.Event{{Introduced: "5.5.0"}, {Fixed: "5.10.235"}}},
				{Events: []osvschema.Event{{Introduced: "5.11.0"}, {Fixed: "5.15.179"}}},
				{Events: []osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.129"}}},
				{Events: []osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.79"}}},
				{Events: []osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.16"}}},
				{Events: []osvschema.Event{{Introduced: "6.13.0"}, {Fixed: "6.13.4"}}},
			},
		},
		{
			name: "CVE-2025-21631",
			cve:  loadTestData(t, "CVE-2025-21631"),
			expectedRanges: []osvschema.Range{
				{Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.15.177"}}},
				{Events: []osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.125"}}},
				{Events: []osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.72"}}},
				{Events: []osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.10"}}},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var affectedBlock cves.Affected
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
			gotRanges, _, _ := findInverseAffectedRanges(affectedBlock, tc.cve.Metadata.AssignerShortName)

			// Sort slices for deterministic comparison.
			sort.Slice(gotRanges, func(i, j int) bool {
				if len(gotRanges[i].Events) == 0 || len(gotRanges[j].Events) == 0 {
					return false
				}
				eventI := gotRanges[i].Events[0]
				eventJ := gotRanges[j].Events[0]
				if eventI.Introduced != "" && eventJ.Introduced != "" {
					return eventI.Introduced < eventJ.Introduced
				}
				if eventI.Fixed != "" && eventJ.Fixed != "" {
					return eventI.Fixed < eventJ.Fixed
				}

				return eventI.Introduced != ""
			})

			sort.Slice(tc.expectedRanges, func(i, j int) bool {
				if len(tc.expectedRanges[i].Events) == 0 || len(tc.expectedRanges[j].Events) == 0 {
					return false
				}
				eventI := tc.expectedRanges[i].Events[0]
				eventJ := tc.expectedRanges[j].Events[0]
				if eventI.Introduced != "" && eventJ.Introduced != "" {
					return eventI.Introduced < eventJ.Introduced
				}
				if eventI.Fixed != "" && eventJ.Fixed != "" {
					return eventI.Fixed < eventJ.Fixed
				}

				return eventI.Introduced != ""
			})

			if diff := cmp.Diff(tc.expectedRanges, gotRanges); diff != "" {
				t.Errorf("findInverseAffectedRanges() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
