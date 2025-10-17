package cvelist2osv

import (
	"reflect"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/vulns"
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
				cves.BuildVersionRange("1.0", "", "1.5"),
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
				cves.BuildVersionRange("0", "2.0", ""),
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
				cves.BuildVersionRange("2.0", "", "2.5"),
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
				cves.BuildVersionRange("", "deadbeef", ""),
			},
			wantRangeType: VersionRangeTypeGit,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			versionExtractor := &DefaultVersionExtractor{}
			gotRanges, gotRangeType := versionExtractor.FindNormalAffectedRanges(tt.affected, &ConversionMetrics{})
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
				cves.BuildVersionRange("5.0.0", "", "5.10.1"),
			},
		},
		{
			name: "not linux",
			affected: cves.Affected{
				Versions: []cves.Versions{
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
				cves.BuildVersionRange("4.0.0", "", "4.5.2"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metrics := &ConversionMetrics{}
			gotRanges, gotVersionType := findInverseAffectedRanges(tt.affected, metrics)
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
			gotRanges, _ := findInverseAffectedRanges(affectedBlock, &ConversionMetrics{})

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

func TestGetVersionExtractor(t *testing.T) {
	testCases := []struct {
		name         string
		cve          cves.CVE5
		expectedType reflect.Type
	}{
		{
			name: "Linux CVE",
			cve: cves.CVE5{
				Metadata: cves.CVE5Metadata{
					AssignerShortName: "Linux",
				},
			},
			expectedType: reflect.TypeOf(&LinuxVersionExtractor{}),
		},
		{
			name: "Default CVE",
			cve: cves.CVE5{
				Metadata: cves.CVE5Metadata{
					AssignerShortName: "Anything",
				},
			},
			expectedType: reflect.TypeOf(&DefaultVersionExtractor{}),
		},
		{
			name:         "Empty provider",
			cve:          cves.CVE5{},
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

func TestExtractVersions(t *testing.T) {
	testCases := []struct {
		name             string
		cve              cves.CVE5
		cnaAssigner      string
		repos            []string
		expectedAffected []osvschema.Affected
	}{
		{
			name:  "CVE-2025-1110",
			cve:   loadTestData(t, "CVE-2025-1110"),
			repos: []string{"https://gitlab.com/gitlab-org/gitlab"},
			expectedAffected: []osvschema.Affected{{
				Ranges: []osvschema.Range{{
					Type: "GIT",
					Repo: "https://gitlab.com/gitlab-org/gitlab",
					Events: []osvschema.Event{
						{Introduced: "504fd9e5236e13d674e051c6b8a1e9892b371c58"},
						{Fixed: "3426be1b93852c5358240c5df40970c0ddfbdb2a"},
					},
					DatabaseSpecific: map[string]any{
						"versions": []osvschema.Event{{Introduced: "18.0"}, {Fixed: "18.0.1"}},
					},
				}},
			}},
		},
		{
			name:  "CVE-2024-21634",
			cve:   loadTestData(t, "CVE-2024-21634"),
			repos: []string{"https://github.com/amazon-ion/ion-java"},
			expectedAffected: []osvschema.Affected{{
				Ranges: []osvschema.Range{{
					Type: "GIT",
					Repo: "https://github.com/amazon-ion/ion-java",
					Events: []osvschema.Event{
						{Introduced: "0"},
						{Fixed: "019a6117fb99131f74f92ecf462169613234abbf"},
					},
					DatabaseSpecific: map[string]any{
						"versions": []osvschema.Event{{Introduced: "0"}, {Fixed: "1.10.5"}},
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
			expectedAffected: []osvschema.Affected{{
				Ranges: []osvschema.Range{{
					Type: "GIT",
					Events: []osvschema.Event{
						{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
						{Fixed: "a3e77da9f843e4ab93917d30c314f0283e28c124"},
					},
					Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
				},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "213ba5bd81b7e97ac6e6190b8f3bc6ba76123625"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "40a35d14f3c0dc72b689061ec72fc9b193f37d1f"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "27a39d006f85e869be68c1d5d2ce05e5d6445bf5"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "92527100be38ede924768f4277450dfe8a40e16b"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "6578717ebca91678131d2b1f4ba4258e60536e9f"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "7fa9706722882f634090bfc9af642bf9ed719e27"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					},
					{
						Type: "GIT",
						Events: []osvschema.Event{
							{Introduced: "1da177e4c3f41524e886b7f1b8a0c1fc7321cac2"},
							{Fixed: "80e648042e512d5a767da251d44132553fe04ae0"},
						},
						Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git",
					}},
			},
				{
					Package: osvschema.Package{Ecosystem: "Linux", Name: "Kernel"},
					Ranges: []osvschema.Range{
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "0"}, {Fixed: "5.4.291"}}},
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "5.5.0"}, {Fixed: "5.10.235"}}},
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "5.11.0"}, {Fixed: "5.15.179"}}},
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "5.16.0"}, {Fixed: "6.1.129"}}},
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "6.2.0"}, {Fixed: "6.6.79"}}},
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "6.7.0"}, {Fixed: "6.12.16"}}},
						{Type: "ECOSYSTEM", Events: []osvschema.Event{{Introduced: "6.13.0"}, {Fixed: "6.13.4"}}},
					},
				}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metrics := &ConversionMetrics{}
			var v vulns.Vulnerability
			extractor := GetVersionExtractor(tc.cnaAssigner)
			extractor.ExtractVersions(tc.cve, &v, metrics, tc.repos)

			if diff := cmp.Diff(tc.expectedAffected, v.Affected); diff != "" {
				t.Errorf("ExtractVersions() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
