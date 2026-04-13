package main

import (
	"fmt"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	gitpurl "github.com/google/osv/vulnfeeds/git"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const testdataPath = "../../test_data/combine-to-osv"

func TestLoadOSV(t *testing.T) {
	cve5Path := filepath.Join(testdataPath, "cve5")
	allVulns := loadOSV(cve5Path)

	if len(allVulns) != 4 {
		t.Errorf("Expected 4 vulnerabilities, got %d", len(allVulns))
	}

	if _, ok := allVulns["CVE-2023-1234"]; !ok {
		t.Error("Expected to load CVE-2023-1234")
	}
}

func TestCombineIntoOSV(t *testing.T) {
	cve5Path := filepath.Join(testdataPath, "cve5")
	nvdPath := filepath.Join(testdataPath, "nvd")

	cve5osv := loadOSV(cve5Path)
	nvdosv := loadOSV(nvdPath)
	nvdosvCopy := make(map[models.CVEID]*osvschema.Vulnerability)
	for k, v := range nvdosv {
		nvdosvCopy[k] = v
	}
	noPkgCVEs := []string{"CVE-2023-0003"}

	combined := combineIntoOSV(cve5osv, nvdosvCopy, noPkgCVEs)

	// Expected results
	// CVE-2023-1234: merged
	// CVE-2023-0001: from cve5 only
	// CVE-2023-0002: from nvd only
	// CVE-2023-0003: from cve5, no affected, but in noPkgCVEs
	// CVE-2023-0004: from cve5, no affected, not in noPkgCVEs, so skipped
	if len(combined) != 2 {
		t.Errorf("Expected 2 combined vulnerabilities, got %d", len(combined))
	}

	// Test case 1: Merged CVE
	cve1234, ok := combined["CVE-2023-1234"]
	if !ok {
		t.Fatal("Expected combined map to contain CVE-2023-1234")
	}

	// Check modified and published dates
	expectedModified, _ := time.Parse(time.RFC3339, "2023-01-02T12:00:00Z")
	if !cve1234.GetModified().AsTime().Equal(expectedModified) {
		t.Errorf("CVE-2023-1234: expected modified time %v, got %v", expectedModified, cve1234.GetModified())
	}
	expectedPublished, _ := time.Parse(time.RFC3339, "2023-01-01T09:00:00Z")
	if !cve1234.GetPublished().AsTime().Equal(expectedPublished) {
		t.Errorf("CVE-2023-1234: expected published time %v, got %v", expectedPublished, cve1234.GetPublished())
	}

	// Check references
	if len(cve1234.GetReferences()) != 2 {
		t.Errorf("CVE-2023-1234: expected 2 references, got %d", len(cve1234.GetReferences()))
	}

	// Check aliases
	if len(cve1234.GetAliases()) != 2 {
		t.Errorf("CVE-2023-1234: expected 2 aliases, got %d", len(cve1234.GetAliases()))
	}

	// Check affected (based on pickAffectedInformation logic)
	var affectedForRepoA *osvschema.Affected
	foundAffected := false
	for _, a := range cve1234.GetAffected() {
		if len(a.GetRanges()) > 0 && a.GetRanges()[0].GetRepo() == "https://example.com/repo/a" {
			affectedForRepoA = a
			foundAffected = true

			break
		}
	}
	if !foundAffected {
		t.Fatal("Did not find affected for repo https://example.com/repo/a")
	}

	expectedRange := &osvschema.Range{
		Type: osvschema.Range_GIT,
		Repo: "https://example.com/repo/a",
		Events: []*osvschema.Event{
			{Introduced: "1.0.0"},
			{Fixed: "1.0.1"},
		},
	}

	// The current logic for pickAffectedInformation when len(cveRanges) == 1 && len(nvdRanges) == 1
	// is to prefer cve5 data.
	if diff := cmp.Diff(expectedRange, affectedForRepoA.GetRanges()[0], protocmp.Transform()); diff != "" {
		t.Errorf("CVE-2023-1234: affected range mismatch (-want +got):\n%s", diff)
	}

	// Test case 2: CVE only in cve5 (has no ranges, so it should be skipped)
	if _, ok = combined["CVE-2023-0001"]; ok {
		t.Error("Expected combined map to NOT contain CVE-2023-0001 because it has no ranges")
	}

	// Test case 3: CVE only in nvd (has no ranges, so it should be skipped)
	if _, ok = combined["CVE-2023-0002"]; ok {
		t.Error("Expected combined map to NOT contain CVE-2023-0002 because it has no ranges")
	}

	// Test case 4: No ranges, in noPkgCVEs (should be kept)
	if _, ok = combined["CVE-2023-0003"]; !ok {
		t.Error("Expected combined map to contain CVE-2023-0003")
	}

	// Test case 5: No ranges, not in noPkgCVEs (should be skipped)
	if _, ok = combined["CVE-2023-0004"]; ok {
		t.Error("Expected combined map to NOT contain CVE-2023-0004")
	}
}

func TestPickAffectedInformation(t *testing.T) {
	repoA := "https://example.com/repo/a"
	repoB := "https://example.com/repo/b"

	// Base data for tests
	cve5Base := []*osvschema.Affected{
		{
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: repoA,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.1"},
					},
				},
			},
		},
	}

	nvdBase := []*osvschema.Affected{
		{
			Ranges: []*osvschema.Range{
				{
					Type: osvschema.Range_GIT,
					Repo: repoA,
					Events: []*osvschema.Event{
						{Introduced: "1.0.0"},
						{Fixed: "1.0.2"}, // Different fixed version
					},
				},
			},
		},
	}

	testCases := []struct {
		name         string
		cve5Affected []*osvschema.Affected
		nvdAffected  []*osvschema.Affected
		wantAffected []*osvschema.Affected
	}{
		{
			name:         "NVD has more affected packages",
			cve5Affected: cve5Base,
			nvdAffected: append(append([]*osvschema.Affected(nil), nvdBase...), &osvschema.Affected{
				Package: &osvschema.Package{Name: "another"},
			}),
			wantAffected: append(append([]*osvschema.Affected(nil), nvdBase...), &osvschema.Affected{
				Package: &osvschema.Package{Name: "another"},
			}),
		},
		{
			name:         "Same repo, same number of ranges, cve5 data is preferred",
			cve5Affected: cve5Base,
			nvdAffected:  nvdBase,
			// cve5's "1.0.1" fixed version should be kept
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type:   osvschema.Range_GIT,
							Repo:   repoA,
							Events: cve5Base[0].GetRanges()[0].GetEvents(),
						},
					},
				},
			},
		},
		{
			name:         "cve5 is empty, use nvd",
			cve5Affected: []*osvschema.Affected{},
			nvdAffected:  nvdBase,
			wantAffected: nvdBase,
		},
		{
			name:         "nvd is empty, use cve5",
			cve5Affected: cve5Base,
			nvdAffected:  []*osvschema.Affected{},
			wantAffected: cve5Base,
		},
		{
			name: "NVD provides missing introduced version",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Fixed: "1.0.1"}, // No introduced
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"}, // NVD has introduced
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.1"},
							},
						},
					},
				},
			},
		},
		{
			name: "NVD provides missing fixed version",
			cve5Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"}, // No fixed
							},
						},
					},
				},
			},
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "0.9.0"},
								{Fixed: "1.0.2"}, // NVD has fixed
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoA,
							Events: []*osvschema.Event{
								{Introduced: "1.0.0"},
								{Fixed: "1.0.2"},
							},
						},
					},
				},
			},
		},
		{
			name:         "NVD has unmatched repo, should be added",
			cve5Affected: cve5Base,
			nvdAffected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoB, // Different repo
							Events: []*osvschema.Event{
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
			wantAffected: []*osvschema.Affected{
				cve5Base[0], // From cve5
				{
					Ranges: []*osvschema.Range{
						{
							Type: osvschema.Range_GIT,
							Repo: repoB,
							Events: []*osvschema.Event{
								{Introduced: "2.0.0"},
								{Fixed: "2.0.1"},
							},
						},
					},
				},
			},
		},
	}

	// Sorter for comparing slices of Affected, ignoring order.
	sorter := cmpopts.SortSlices(func(a, b *osvschema.Affected) bool {
		if len(a.GetRanges()) == 0 || len(a.GetRanges()[0].GetRepo()) == 0 {
			return true
		}
		if len(b.GetRanges()) == 0 || len(b.GetRanges()[0].GetRepo()) == 0 {
			return false
		}

		return a.GetRanges()[0].GetRepo() < b.GetRanges()[0].GetRepo()
	})

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create a copy to avoid modifying the test case data
			cve5Actual := make([]*osvschema.Affected, len(tc.cve5Affected))
			copy(cve5Actual, tc.cve5Affected)

			gotAffected := pickAffectedInformation(cve5Actual, tc.nvdAffected)

			if diff := cmp.Diff(tc.wantAffected, gotAffected, sorter, protocmp.Transform()); diff != "" {
				t.Errorf("pickAffectedInformation() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestCombineTwoOSVRecords(t *testing.T) {
	cve5Modified, _ := time.Parse(time.RFC3339, "2023-01-01T12:00:00Z")
	cve5Published, _ := time.Parse(time.RFC3339, "2023-01-01T10:00:00Z")
	nvdModified, _ := time.Parse(time.RFC3339, "2023-01-02T12:00:00Z")  // Later
	nvdPublished, _ := time.Parse(time.RFC3339, "2023-01-01T09:00:00Z") // Earlier

	cve5 := &osvschema.Vulnerability{
		Id:        "CVE-2023-1234",
		Modified:  timestamppb.New(cve5Modified),
		Published: timestamppb.New(cve5Published),
		Aliases:   []string{"GHSA-1234"},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5"},
		},
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{Name: "package-a"},
			},
		},
	}

	nvd := &osvschema.Vulnerability{
		Id:        "CVE-2023-1234",
		Modified:  timestamppb.New(nvdModified),
		Published: timestamppb.New(nvdPublished),
		Aliases:   []string{"GHSA-1234", "GHSA-5678"},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5"}, // Duplicate
			{Type: osvschema.Reference_WEB, Url: "https://example.com/nvd"},
		},
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{Name: "package-a"},
			},
			{
				Package: &osvschema.Package{Name: "package-b"},
			},
		},
	}

	expected := &osvschema.Vulnerability{
		Id:        "CVE-2023-1234",
		Modified:  timestamppb.New(nvdModified),  // Should take later date from NVD
		Published: timestamppb.New(nvdPublished), // Should take earlier date from NVD
		Aliases:   []string{"GHSA-1234", "GHSA-5678"},
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5"},
			{Type: osvschema.Reference_WEB, Url: "https://example.com/nvd"},
		},
		// pickAffectedInformation prefers nvd if it has more packages
		Affected: nvd.GetAffected(),
	}

	got := combineTwoOSVRecords(cve5, nvd)

	// Sort slices for consistent comparison
	sort.Strings(got.GetAliases())
	sort.Strings(expected.GetAliases())
	sort.Slice(got.GetReferences(), func(i, j int) bool {
		return got.GetReferences()[i].GetUrl() < got.GetReferences()[j].GetUrl()
	})
	sort.Slice(expected.GetReferences(), func(i, j int) bool {
		return expected.GetReferences()[i].GetUrl() < expected.GetReferences()[j].GetUrl()
	})

	if diff := cmp.Diff(expected, got, protocmp.Transform()); diff != "" {
		t.Errorf("combineTwoOSVRecords() mismatch (-want +got):\n%s", diff)
	}
}

func TestRepoURLFromRanges_GIT(t *testing.T) {
	t.Parallel()

	ranges := []*osvschema.Range{
		{
			Type: osvschema.Range_GIT,
			Repo: "https://github.com/eclipse-openj9/openj9",
			Events: []*osvschema.Event{
				{Introduced: "0"},
			},
		},
	}
	got := repoURLFromRanges(ranges)
	want := "https://github.com/eclipse-openj9/openj9"
	if got != want {
		t.Fatalf("repoURLFromRanges() = %q, want %q", got, want)
	}
}

func TestRepoURLFromRanges_NoGIT(t *testing.T) {
	t.Parallel()

	ranges := []*osvschema.Range{
		{
			Type: osvschema.Range_ECOSYSTEM,
			Events: []*osvschema.Event{
				{Introduced: "0"},
				{Fixed: "1.2.3"},
			},
		},
	}
	if got := repoURLFromRanges(ranges); got != "" {
		t.Fatalf("repoURLFromRanges() = %q, want empty", got)
	}
}

func TestAddVersionedRepoPURLs_FromVersions(t *testing.T) {
	t.Setenv("ENABLE_REPO_PURL_TAGS", "") // ensure derivation path is off

	repo := "https://github.com/chriskohlhoff/asio"
	aff := &osvschema.Affected{
		Package:  &osvschema.Package{Ecosystem: "GIT", Name: "asio"},
		Versions: []string{"asio-1-13-0", "asio-1-12-0"},
		Ranges: []*osvschema.Range{{
			Type:   osvschema.Range_GIT,
			Repo:   repo,
			Events: []*osvschema.Event{{Introduced: "0"}},
		}},
	}

	addVersionedRepoPURLs(aff, repo)

	base, err := gitpurl.BuildGenericRepoPURL(repo)
	if err != nil || base == "" {
		t.Fatalf("failed to build base purl: %v", err)
	}

	field := aff.GetDatabaseSpecific().GetFields()["repo_purls"]
	if field == nil {
		t.Fatalf("repo_purls missing: %#v", aff.GetDatabaseSpecific())
	}
	values := field.GetListValue().GetValues()
	if len(values) == 0 {
		t.Fatalf("repo_purls empty: %#v", aff.GetDatabaseSpecific())
	}
	list := make([]string, 0, len(values))
	for _, v := range values {
		list = append(list, v.GetStringValue())
	}

	want1 := base + "@asio-1-13-0"
	want2 := base + "@asio-1-12-0"
	found1, found2 := false, false
	for _, p := range list {
		if p == want1 {
			found1 = true
		}
		if p == want2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Fatalf("missing expected entries, got %#v", list)
	}
}

// repoPURLs pulls the string list stored under database_specific["repo_purls"]
// so tests can assert on the versioned pURLs attached by enrichRepoPURLs.
func repoPURLs(t *testing.T, aff *osvschema.Affected) []string {
	t.Helper()
	field := aff.GetDatabaseSpecific().GetFields()["repo_purls"]
	if field == nil {
		return nil
	}
	values := field.GetListValue().GetValues()
	out := make([]string, 0, len(values))
	for _, v := range values {
		out = append(out, v.GetStringValue())
	}

	return out
}

func TestEnrichRepoPURLs_Issue3807(t *testing.T) {
	t.Parallel()

	repo := "https://github.com/chriskohlhoff/asio"
	v := &osvschema.Vulnerability{
		Id: "CVE-2019-25219",
		Affected: []*osvschema.Affected{
			{
				Versions: []string{"asio-1-12-0", "asio-1-12-1", "asio-1-13-0"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_GIT,
					Repo:   repo,
					Events: []*osvschema.Event{{Introduced: "0"}},
				}},
			},
		},
	}

	enrichRepoPURLs(v)

	aff := v.Affected[0]
	wantBase := "pkg:generic/github.com/chriskohlhoff/asio"
	if got := aff.GetPackage().GetPurl(); got != wantBase {
		t.Errorf("package.purl = %q, want %q", got, wantBase)
	}

	got := repoPURLs(t, aff)
	want := []string{
		wantBase + "@asio-1-12-0",
		wantBase + "@asio-1-12-1",
		wantBase + "@asio-1-13-0",
	}
	sort.Strings(got)
	sort.Strings(want)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("repo_purls mismatch (-want +got):\n%s", diff)
	}
}

func TestEnrichRepoPURLs_PreservesExistingPurl(t *testing.T) {
	t.Parallel()

	existing := "pkg:deb/debian/libasio-dev"
	v := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package:  &osvschema.Package{Purl: existing},
				Versions: []string{"asio-1-12-0"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_GIT,
					Repo:   "https://github.com/chriskohlhoff/asio",
					Events: []*osvschema.Event{{Introduced: "0"}},
				}},
			},
		},
	}

	enrichRepoPURLs(v)

	if got := v.Affected[0].GetPackage().GetPurl(); got != existing {
		t.Errorf("package.purl clobbered: got %q, want %q", got, existing)
	}
	if got := repoPURLs(t, v.Affected[0]); len(got) == 0 {
		t.Errorf("expected repo_purls to be populated, got none")
	}
}

func TestEnrichRepoPURLs_NonGITRangeNoop(t *testing.T) {
	t.Parallel()

	v := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package:  &osvschema.Package{Ecosystem: "Debian:11", Name: "libasio"},
				Versions: []string{"1.18.1"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.18.2"}},
				}},
			},
		},
	}

	enrichRepoPURLs(v)

	if got := v.Affected[0].GetPackage().GetPurl(); got != "" {
		t.Errorf("package.purl = %q, want empty (no GIT range)", got)
	}
	if got := repoPURLs(t, v.Affected[0]); len(got) != 0 {
		t.Errorf("repo_purls should be absent, got %v", got)
	}
}

func TestEnrichRepoPURLs_DotGitSuffix(t *testing.T) {
	t.Parallel()

	v := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Versions: []string{"v1.2.11"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_GIT,
					Repo:   "https://github.com/madler/zlib.git",
					Events: []*osvschema.Event{{Introduced: "0"}},
				}},
			},
		},
	}

	enrichRepoPURLs(v)

	wantBase := "pkg:generic/github.com/madler/zlib"
	if got := v.Affected[0].GetPackage().GetPurl(); got != wantBase {
		t.Errorf("package.purl = %q, want %q (.git suffix should be stripped)", got, wantBase)
	}
	want := []string{wantBase + "@v1.2.11"}
	if diff := cmp.Diff(want, repoPURLs(t, v.Affected[0])); diff != "" {
		t.Errorf("repo_purls mismatch (-want +got):\n%s", diff)
	}
}

func TestEnrichRepoPURLs_MultipleAffectedOnlyGITEnriched(t *testing.T) {
	t.Parallel()

	v := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Package:  &osvschema.Package{Ecosystem: "Debian:11", Name: "libasio"},
				Versions: []string{"1.18.1"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_ECOSYSTEM,
					Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "1.18.2"}},
				}},
			},
			{
				Versions: []string{"asio-1-12-0"},
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_GIT,
					Repo:   "https://github.com/chriskohlhoff/asio",
					Events: []*osvschema.Event{{Introduced: "0"}},
				}},
			},
		},
	}

	enrichRepoPURLs(v)

	if got := v.Affected[0].GetPackage().GetPurl(); got != "" {
		t.Errorf("affected[0] (ECOSYSTEM) package.purl = %q, want empty", got)
	}
	if got := repoPURLs(t, v.Affected[0]); len(got) != 0 {
		t.Errorf("affected[0] (ECOSYSTEM) repo_purls should be empty, got %v", got)
	}

	wantBase := "pkg:generic/github.com/chriskohlhoff/asio"
	if got := v.Affected[1].GetPackage().GetPurl(); got != wantBase {
		t.Errorf("affected[1] (GIT) package.purl = %q, want %q", got, wantBase)
	}
	if got := repoPURLs(t, v.Affected[1]); len(got) != 1 || got[0] != wantBase+"@asio-1-12-0" {
		t.Errorf("affected[1] (GIT) repo_purls = %v, want [%s@asio-1-12-0]", got, wantBase)
	}
}

func TestAddVersionedRepoPURLs_EscapesSpecialCharsInTags(t *testing.T) {
	t.Parallel()

	repo := "https://github.com/example/repo"
	aff := &osvschema.Affected{
		Versions: []string{"release/1.2.3", "v1.0 beta", "rel#1"},
		Ranges: []*osvschema.Range{{
			Type: osvschema.Range_GIT,
			Repo: repo,
		}},
	}

	addVersionedRepoPURLs(aff, repo)

	got := repoPURLs(t, aff)
	want := []string{
		"pkg:generic/github.com/example/repo@rel%231",
		"pkg:generic/github.com/example/repo@release%2F1.2.3",
		"pkg:generic/github.com/example/repo@v1.0%20beta",
	}
	sort.Strings(got)
	sort.Strings(want)
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("repo_purls mismatch (-want +got):\n%s", diff)
	}
}

func TestAddVersionedRepoPURLs_CapsLargeVersionLists(t *testing.T) {
	t.Parallel()

	versions := make([]string, maxRepoPURLTags+50)
	for i := range versions {
		versions[i] = fmt.Sprintf("v1.0.%d", i)
	}
	aff := &osvschema.Affected{
		Versions: versions,
		Ranges: []*osvschema.Range{{
			Type: osvschema.Range_GIT,
			Repo: "https://github.com/example/big",
		}},
	}

	addVersionedRepoPURLs(aff, "https://github.com/example/big")

	got := repoPURLs(t, aff)
	if len(got) != maxRepoPURLTags {
		t.Errorf("len(repo_purls) = %d, want %d", len(got), maxRepoPURLTags)
	}
}

func TestCombineTwoOSVRecords_ReferencesDeterminism(t *testing.T) {
	cve5 := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5/A"},
			{Type: osvschema.Reference_REPORT, Url: "https://example.com/cve5/B"},
		},
	}

	nvd := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
		References: []*osvschema.Reference{
			{Type: osvschema.Reference_WEB, Url: "https://example.com/cve5/A"},
			{Type: osvschema.Reference_WEB, Url: "https://example.com/nvd/C"},
			{Type: osvschema.Reference_ADVISORY, Url: "https://example.com/nvd/D"},
		},
	}

	var firstResult *osvschema.Vulnerability
	for i := range 10 {
		got := combineTwoOSVRecords(cve5, nvd)

		if i == 0 {
			firstResult = got
			continue
		}

		if diff := cmp.Diff(firstResult.GetReferences(), got.GetReferences(), protocmp.Transform()); diff != "" {
			t.Fatalf("Iteration %d produced different references result:\n%s", i, diff)
		}
	}
}
