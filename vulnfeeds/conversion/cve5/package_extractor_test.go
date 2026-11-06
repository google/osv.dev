package cve5

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

// stubExtractor appends a fixed affected entry, standing in for the Git range extraction.
type stubExtractor struct {
	called  bool
	outcome models.ConversionOutcome
}

func (s *stubExtractor) ExtractVersions(_ models.CVE5, v *vulns.Vulnerability, metrics *models.ConversionMetrics, _ []string, _ git.RepoTagsCache, _ *http.Client) {
	s.called = true
	metrics.Outcome = s.outcome
	v.Affected = append(v.Affected, &osvschema.Affected{
		Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://github.com/example/repo"}},
	})
}

func ecosystemRange(events ...*osvschema.Event) *osvschema.Range {
	return &osvschema.Range{Type: osvschema.Range_ECOSYSTEM, Events: events}
}

func introduced(v string) *osvschema.Event { return &osvschema.Event{Introduced: v} }
func fixed(v string) *osvschema.Event      { return &osvschema.Event{Fixed: v} }
func lastAffected(v string) *osvschema.Event {
	return &osvschema.Event{LastAffected: v}
}

func extractPackageAffected(t *testing.T, affected []models.Affected) ([]*osvschema.Affected, *models.ConversionMetrics, *stubExtractor) {
	t.Helper()

	cve := models.CVE5{}
	cve.Containers.CNA.Affected = affected
	v := &vulns.Vulnerability{Vulnerability: &osvschema.Vulnerability{Id: "CVE-2025-00000"}}
	metrics := &models.ConversionMetrics{}
	base := &stubExtractor{}

	extractor := &PackageVersionExtractor{Base: base}
	extractor.ExtractVersions(cve, v, metrics, nil, nil, nil)

	return v.Affected, metrics, base
}

func TestPackageVersionExtractor_AddsPackageAfterBase(t *testing.T) {
	// Modeled on CVE-2025-68161 (Apache Log4j Core).
	affected, metrics, base := extractPackageAffected(t, []models.Affected{{
		PackageName: "org.apache.logging.log4j:log4j-core",
		PackageURL:  "pkg:maven/org.apache.logging.log4j/log4j-core",
		Versions: []models.Versions{
			{Version: "2.0-beta9", LessThan: "2.25.3", Status: "affected", VersionType: "maven"},
			{Version: "3.0.0-alpha1", LessThanOrEqual: "3.0.0-beta3", Status: "affected", VersionType: "maven"},
		},
	}})

	if !base.called {
		t.Error("base extractor was not called")
	}

	want := []*osvschema.Affected{
		{Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://github.com/example/repo"}}},
		{
			Package: &osvschema.Package{
				Ecosystem: "Maven",
				Name:      "org.apache.logging.log4j:log4j-core",
				Purl:      "pkg:maven/org.apache.logging.log4j/log4j-core",
			},
			Ranges: []*osvschema.Range{
				ecosystemRange(introduced("2.0-beta9"), fixed("2.25.3")),
				ecosystemRange(introduced("3.0.0-alpha1"), lastAffected("3.0.0-beta3")),
			},
		},
	}
	if diff := cmp.Diff(want, affected, protocmp.Transform()); diff != "" {
		t.Errorf("affected mismatch (-want +got):\n%s", diff)
	}
	if metrics.ResolvedRangesCount != 2 {
		t.Errorf("ResolvedRangesCount = %d, want 2", metrics.ResolvedRangesCount)
	}
}

func TestPackageVersionExtractor_SharedRangeAcrossPackages(t *testing.T) {
	// Bouncy Castle lists several artifacts per CVE, often with an identical range.
	affected, _, _ := extractPackageAffected(t, []models.Affected{
		{
			PackageURL: "pkg:maven/org.bouncycastle/bcprov-jdk18on",
			Versions:   []models.Versions{{Version: "0", LessThan: "1.86", Status: "affected", VersionType: "maven"}},
		},
		{
			PackageURL: "pkg:maven/org.bouncycastle/bcpkix-jdk18on",
			Versions:   []models.Versions{{Version: "0", LessThan: "1.86", Status: "affected", VersionType: "maven"}},
		},
	})

	var names []string
	for _, a := range affected {
		if a.GetPackage() == nil {
			continue
		}
		names = append(names, a.GetPackage().GetName())
		if len(a.GetRanges()) != 1 {
			t.Errorf("%s has %d ranges, want 1", a.GetPackage().GetName(), len(a.GetRanges()))
		}
	}
	want := []string{"org.bouncycastle:bcprov-jdk18on", "org.bouncycastle:bcpkix-jdk18on"}
	if diff := cmp.Diff(want, names); diff != "" {
		t.Errorf("packages mismatch (-want +got):\n%s", diff)
	}
}

func TestPackageVersionExtractor_CombinesBlocksForSamePackage(t *testing.T) {
	affected, _, _ := extractPackageAffected(t, []models.Affected{
		{
			PackageURL: "pkg:npm/@fastify/middie",
			Versions:   []models.Versions{{Version: "9.1.0", LessThan: "9.3.3", Status: "affected", VersionType: "semver"}},
		},
		{
			PackageURL: "pkg:npm/%40fastify/middie",
			Versions:   []models.Versions{{Version: "0", LessThan: "8.3.4", Status: "affected", VersionType: "semver"}},
		},
	})

	if len(affected) != 2 {
		t.Fatalf("got %d affected entries, want the base entry and 1 package entry: %v", len(affected), affected)
	}
	pkg := affected[1]
	if pkg.GetPackage().GetName() != "@fastify/middie" {
		t.Errorf("package name = %q, want @fastify/middie", pkg.GetPackage().GetName())
	}
	want := []*osvschema.Range{
		ecosystemRange(introduced("9.1.0"), fixed("9.3.3")),
		ecosystemRange(introduced("0"), fixed("8.3.4")),
	}
	if diff := cmp.Diff(want, pkg.GetRanges(), protocmp.Transform()); diff != "" {
		t.Errorf("ranges mismatch (-want +got):\n%s", diff)
	}
}

func TestPackageVersionExtractor_SkipsWhatItCannotMap(t *testing.T) {
	tests := []struct {
		name     string
		affected models.Affected
		wantNote string
	}{
		{
			name: "no purl",
			affected: models.Affected{
				Versions: []models.Versions{{Version: "0", LessThan: "1.0", Status: "affected", VersionType: "semver"}},
			},
		},
		{
			name: "unsupported purl type",
			affected: models.Affected{
				PackageURL: "pkg:cpan/Lucy",
				Versions:   []models.Versions{{Version: "0", LessThan: "1.0", Status: "affected", VersionType: "semver"}},
			},
			wantNote: "unsupported purl type",
		},
		{
			name: "invalid purl",
			affected: models.Affected{
				PackageURL: "not-a-purl",
				Versions:   []models.Versions{{Version: "0", LessThan: "1.0", Status: "affected", VersionType: "semver"}},
			},
			wantNote: "Skipping package versions",
		},
		{
			name: "only unaffected versions",
			affected: models.Affected{
				PackageURL: "pkg:npm/lodash",
				Versions:   []models.Versions{{Version: "4.17.21", Status: "unaffected", VersionType: "semver"}},
			},
		},
		{
			name: "git versions are left to the base extractor",
			affected: models.Affected{
				PackageURL: "pkg:pypi/paramiko",
				Versions: []models.Versions{{
					Version:     "0",
					LessThan:    "a4489456b6f65281e172380cc4826cee5e851dbb",
					Status:      "affected",
					VersionType: "git",
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			affected, metrics, _ := extractPackageAffected(t, []models.Affected{tt.affected})
			if len(affected) != 1 || affected[0].GetPackage() != nil {
				t.Errorf("expected only the base entry, got %v", affected)
			}
			if metrics.ResolvedRangesCount != 0 {
				t.Errorf("ResolvedRangesCount = %d, want 0", metrics.ResolvedRangesCount)
			}
			if tt.wantNote != "" && !strings.Contains(strings.Join(metrics.Notes, "\n"), tt.wantNote) {
				t.Errorf("notes %q do not mention %q", metrics.Notes, tt.wantNote)
			}
		})
	}
}

func TestPackageVersionExtractor_SingleVersion(t *testing.T) {
	affected, _, _ := extractPackageAffected(t, []models.Affected{{
		PackageURL: "pkg:maven/org.example/lib",
		Versions:   []models.Versions{{Version: "1.2.3", Status: "affected", VersionType: "maven"}},
	}})

	want := []*osvschema.Range{ecosystemRange(introduced("1.2.3"), lastAffected("1.2.3"))}
	if diff := cmp.Diff(want, affected[len(affected)-1].GetRanges(), protocmp.Transform()); diff != "" {
		t.Errorf("ranges mismatch (-want +got):\n%s", diff)
	}
}

func TestPackageVersionExtractor_NilBaseUsesDefaultExtractor(t *testing.T) {
	cve := models.CVE5{}
	cve.Containers.CNA.Affected = []models.Affected{{
		PackageURL: "pkg:npm/lodash",
		Versions:   []models.Versions{{Version: "0", LessThan: "4.17.21", Status: "affected", VersionType: "semver"}},
	}}
	v := &vulns.Vulnerability{Vulnerability: &osvschema.Vulnerability{}}

	(&PackageVersionExtractor{}).ExtractVersions(cve, v, &models.ConversionMetrics{}, nil, nil, nil)

	// Only the default extractor records ranges it could not resolve to commits.
	if v.GetDatabaseSpecific().GetFields()["unresolved_ranges"] == nil {
		t.Error("expected unresolved_ranges from the default extractor")
	}
	if len(v.Affected) != 1 || v.Affected[0].GetPackage().GetName() != "lodash" {
		t.Errorf("unexpected affected: %v", v.Affected)
	}
}

func TestPackageVersionExtractor_Outcome(t *testing.T) {
	withPackage := models.Affected{
		PackageURL: "pkg:npm/lodash",
		Versions:   []models.Versions{{Version: "0", LessThan: "4.17.21", Status: "affected", VersionType: "semver"}},
	}
	withoutPackage := models.Affected{
		Versions: []models.Versions{{Version: "0", LessThan: "4.17.21", Status: "affected", VersionType: "semver"}},
	}

	tests := []struct {
		name     string
		affected models.Affected
		base     models.ConversionOutcome
		want     models.ConversionOutcome
	}{
		{"no repos but a package", withPackage, models.NoRepos, models.Successful},
		{"unresolved commits but a package", withPackage, models.NoCommitRanges, models.Successful},
		{"no ranges but a package", withPackage, models.NoRanges, models.Successful},
		{"already successful", withPackage, models.Successful, models.Successful},
		{"an error stays an error", withPackage, models.Error, models.Error},
		{"no package leaves no repos", withoutPackage, models.NoRepos, models.NoRepos},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cve := models.CVE5{}
			cve.Containers.CNA.Affected = []models.Affected{tt.affected}
			v := &vulns.Vulnerability{Vulnerability: &osvschema.Vulnerability{}}
			metrics := &models.ConversionMetrics{}

			(&PackageVersionExtractor{Base: &stubExtractor{outcome: tt.base}}).ExtractVersions(cve, v, metrics, nil, nil, nil)

			if metrics.Outcome != tt.want {
				t.Errorf("Outcome = %v, want %v", metrics.Outcome, tt.want)
			}
		})
	}
}

func TestExtractVersions_PackageCNAs(t *testing.T) {
	tests := []struct {
		cveID string
		cna   string
		want  []*osvschema.Affected
	}{
		{
			cveID: "CVE-2025-68161",
			cna:   "apache",
			want: []*osvschema.Affected{{
				Package: &osvschema.Package{
					Ecosystem: "Maven",
					Name:      "org.apache.logging.log4j:log4j-core",
					Purl:      "pkg:maven/org.apache.logging.log4j/log4j-core",
				},
				Ranges: []*osvschema.Range{
					ecosystemRange(introduced("2.0-beta9"), fixed("2.25.3")),
					ecosystemRange(introduced("3.0.0-alpha1"), lastAffected("3.0.0-beta3")),
				},
			}},
		},
		{
			// Two artifacts in one record, each with its own range.
			cveID: "CVE-2026-97873",
			cna:   "bcorg",
			want: []*osvschema.Affected{
				{
					Package: &osvschema.Package{
						Ecosystem: "Maven",
						Name:      "org.bouncycastle:bcprov-jdk18on",
						Purl:      "pkg:maven/org.bouncycastle/bcprov-jdk18on",
					},
					Ranges: []*osvschema.Range{ecosystemRange(introduced("0"), fixed("1.86"))},
				},
				{
					Package: &osvschema.Package{
						Ecosystem: "Maven",
						Name:      "org.bouncycastle:bcprov-lts8on",
						Purl:      "pkg:maven/org.bouncycastle/bcprov-lts8on",
					},
					Ranges: []*osvschema.Range{ecosystemRange(introduced("2.73.0"), fixed("2.73.13"))},
				},
			},
		},
		{
			// A scoped npm package, with a literal "@" in the purl.
			cveID: "CVE-2026-15631",
			cna:   "OpenJS",
			want: []*osvschema.Affected{{
				Package: &osvschema.Package{
					Ecosystem: "npm",
					Name:      "@fastify/http-proxy",
					Purl:      "pkg:npm/%40fastify/http-proxy",
				},
				Ranges: []*osvschema.Range{ecosystemRange(introduced("9.4.0"), fixed("11.6.0"))},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.cveID, func(t *testing.T) {
			v := &vulns.Vulnerability{Vulnerability: &osvschema.Vulnerability{Id: tt.cveID}}
			// No repos, so only the package ranges are produced and no Git access is needed.
			GetVersionExtractor(tt.cna).ExtractVersions(loadTestData(t, tt.cveID), v, &models.ConversionMetrics{}, nil, &git.InMemoryRepoTagsCache{}, http.DefaultClient)

			var got []*osvschema.Affected
			for _, a := range v.Affected {
				if a.GetPackage() != nil {
					got = append(got, a)
				}
			}
			if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
				t.Errorf("package affected mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
