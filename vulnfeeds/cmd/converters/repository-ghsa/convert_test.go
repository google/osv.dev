// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility"
	"github.com/google/osv.dev/vulnfeeds/vulns"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/testing/protocmp"
)

func TestSplitCompoundRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{
			name:  "standard single range",
			input: ">= 1.0.0, < 2.0.0",
			want:  []string{">= 1.0.0, < 2.0.0"},
		},
		{
			name:  "single bound",
			input: "< 2.0.0",
			want:  []string{"< 2.0.0"},
		},
		{
			name:  "compound multiple ranges",
			input: "< 1.2.0, >= 2.0.0, < 2.1.0",
			want:  []string{"< 1.2.0", ">= 2.0.0, < 2.1.0"},
		},
		{
			name:  "compound disjoint lower bounds",
			input: "< 1.0.0, >= 2.0.0",
			want:  []string{"< 1.0.0", ">= 2.0.0"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := splitCompoundRanges(tc.input)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("splitCompoundRanges(%q) mismatch (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestParseAdvisoryVersionRanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		vRange          string
		patchedVersions string
		want            []models.AffectedVersion
	}{
		{
			name:   "standard range",
			vRange: ">= 1.0.0, < 2.0.0",
			want: []models.AffectedVersion{
				{Introduced: "1.0.0", Fixed: "2.0.0"},
			},
		},
		{
			name:   "less than",
			vRange: "< 1.5.0",
			want: []models.AffectedVersion{
				{Introduced: "0", Fixed: "1.5.0"},
			},
		},
		{
			name:   "less than or equal",
			vRange: "<= 1.5.0",
			want: []models.AffectedVersion{
				{Introduced: "0", LastAffected: "1.5.0"},
			},
		},
		{
			name:   "exact version with equal sign",
			vRange: "= 2.1.0",
			want: []models.AffectedVersion{
				{Introduced: "2.1.0", LastAffected: "2.1.0"},
			},
		},
		{
			name:   "bare version string",
			vRange: "2.1.0",
			want: []models.AffectedVersion{
				{Introduced: "2.1.0", LastAffected: "2.1.0"},
			},
		},
		{
			name:            "fallback to patched_versions when vRange is empty",
			vRange:          "",
			patchedVersions: "1.2.3, 2.0.0",
			want: []models.AffectedVersion{
				{Introduced: "0", Fixed: "1.2.3"},
				{Introduced: "0", Fixed: "2.0.0"},
			},
		},
		{
			name:            "supplement fixed with patched_versions when last_affected present",
			vRange:          "<= 1.2.2",
			patchedVersions: "1.2.3",
			want: []models.AffectedVersion{
				{Introduced: "0", Fixed: "1.2.3", LastAffected: "1.2.2"},
			},
		},
		{
			name:   "compound range",
			vRange: "< 1.2.0, >= 2.0.0, < 2.1.0",
			want: []models.AffectedVersion{
				{Introduced: "0", Fixed: "1.2.0"},
				{Introduced: "2.0.0", Fixed: "2.1.0"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := ParseAdvisoryVersionRanges(tc.vRange, tc.patchedVersions)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("ParseAdvisoryVersionRanges(%q, %q) mismatch (-want +got):\n%s", tc.vRange, tc.patchedVersions, diff)
			}
		})
	}
}

func TestResolveRangeToGit(t *testing.T) {
	t.Parallel()

	normalizedTags := map[string]git.NormalizedTag{
		"1-0-0": {Commit: "1111111111111111111111111111111111111111", OriginalTag: "v1.0.0"},
		"2-0-0": {Commit: "2222222222222222222222222222222222222222", OriginalTag: "v2.0.0"},
	}

	repoURL := "https://github.com/owner/repo"

	t.Run("resolved introduced and fixed", func(t *testing.T) {
		av := models.AffectedVersion{
			Introduced: "1.0.0",
			Fixed:      "2.0.0",
		}
		got := resolveRangeToGit(av, repoURL, normalizedTags, "GHSA-test")
		if got == nil {
			t.Fatal("expected git range, got nil")
		}

		dbSpec, err := utility.NewStructpbFromMap(map[string]any{
			"extracted_events": []*osvschema.Event{
				{Introduced: "1.0.0"},
				{Fixed: "2.0.0"},
			},
			"source": string(models.VersionSourceAffected),
		})
		if err != nil {
			t.Fatalf("failed constructing expected database_specific: %v", err)
		}

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "1111111111111111111111111111111111111111"},
				{Fixed: "2222222222222222222222222222222222222222"},
			},
			DatabaseSpecific: dbSpec,
		}

		if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
			t.Errorf("resolveRangeToGit mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("resolved dawn of time introduced", func(t *testing.T) {
		av := models.AffectedVersion{
			Introduced: "0",
			Fixed:      "2.0.0",
		}
		got := resolveRangeToGit(av, repoURL, normalizedTags, "GHSA-test")
		if got == nil {
			t.Fatal("expected git range, got nil")
		}

		dbSpec, err := utility.NewStructpbFromMap(map[string]any{
			"extracted_events": []*osvschema.Event{
				{Introduced: "0"},
				{Fixed: "2.0.0"},
			},
			"source": string(models.VersionSourceAffected),
		})
		if err != nil {
			t.Fatalf("failed constructing expected database_specific: %v", err)
		}

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "0"},
				{Fixed: "2222222222222222222222222222222222222222"},
			},
			DatabaseSpecific: dbSpec,
		}

		if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
			t.Errorf("resolveRangeToGit mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("resolved last_affected", func(t *testing.T) {
		av := models.AffectedVersion{
			Introduced:   "0",
			LastAffected: "1.0.0",
		}
		got := resolveRangeToGit(av, repoURL, normalizedTags, "GHSA-test")
		if got == nil {
			t.Fatal("expected git range, got nil")
		}

		dbSpec, err := utility.NewStructpbFromMap(map[string]any{
			"extracted_events": []*osvschema.Event{
				{Introduced: "0"},
				{LastAffected: "1.0.0"},
			},
			"source": string(models.VersionSourceAffected),
		})
		if err != nil {
			t.Fatalf("failed constructing expected database_specific: %v", err)
		}

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "0"},
				{LastAffected: "1111111111111111111111111111111111111111"},
			},
			DatabaseSpecific: dbSpec,
		}

		if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
			t.Errorf("resolveRangeToGit mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("open vulnerability (no fixed version)", func(t *testing.T) {
		av := models.AffectedVersion{
			Introduced: "1.0.0",
		}
		got := resolveRangeToGit(av, repoURL, normalizedTags, "GHSA-test")
		if got == nil {
			t.Fatal("expected git range, got nil")
		}

		dbSpec, err := utility.NewStructpbFromMap(map[string]any{
			"extracted_events": []*osvschema.Event{
				{Introduced: "1.0.0"},
			},
			"source": string(models.VersionSourceAffected),
		})
		if err != nil {
			t.Fatalf("failed constructing expected database_specific: %v", err)
		}

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "1111111111111111111111111111111111111111"},
			},
			DatabaseSpecific: dbSpec,
		}

		if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
			t.Errorf("resolveRangeToGit mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("unresolvable version returns nil", func(t *testing.T) {
		av := models.AffectedVersion{
			Introduced: "0",
			Fixed:      "9.9.9",
		}
		got := resolveRangeToGit(av, repoURL, normalizedTags, "GHSA-test")
		if got != nil {
			t.Errorf("expected nil for unresolvable version, got %+v", got)
		}
	})
}

func TestConvertAdvisoryToOSV_Full(t *testing.T) {
	t.Parallel()

	cveID := "CVE-2026-99999"
	desc := "Vulnerability details with link to https://example.com/exploit"
	severityLevel := "high"
	v3Vector := "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
	v3Score := 9.8
	v4Vector := "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
	v4Score := 9.3
	pubTime := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	modTime := time.Date(2026, 3, 2, 12, 0, 0, 0, time.UTC)

	pkgName := "my-awesome-lib"
	vRange := ">= 1.0.0, < 2.0.0"

	advisory := GHSAAdvisory{
		GHSAID:      "GHSA-1234-5678-9012",
		CVEID:       &cveID,
		HTMLURL:     "https://github.com/owner/repo/security/advisories/GHSA-1234-5678-9012",
		URL:         "https://api.github.com/repos/owner/repo/security-advisories/GHSA-1234-5678-9012",
		Summary:     "Test vulnerability summary",
		Description: &desc,
		Severity:    &severityLevel,
		State:       "published",
		PublishedAt: &pubTime,
		UpdatedAt:   &modTime,
		Identifiers: []GHSAIdentifier{
			{Type: "GHSA", Value: "GHSA-1234-5678-9012"},
			{Type: "CVE", Value: "CVE-2026-99999"},
		},
		CVSSSeverities: &GHSACVSSSeverities{
			CVSSV3: &GHSACVSS{
				VectorString: &v3Vector,
				Score:        &v3Score,
			},
			CVSSV4: &GHSACVSS{
				VectorString: &v4Vector,
				Score:        &v4Score,
			},
		},
		CWEs: []GHSACWE{
			{CWEID: "CWE-79", Name: "Cross-site Scripting"},
		},
		CWEIDs: []string{"CWE-89"},
		Vulnerabilities: []GHSAVulnerability{
			{
				Package: &GHSAPackage{
					Ecosystem: "npm",
					Name:      &pkgName,
				},
				VulnerableVersionRange: &vRange,
			},
		},
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	normalizedTags := map[string]git.NormalizedTag{
		"1-0-0": {Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OriginalTag: "v1.0.0"},
		"2-0-0": {Commit: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", OriginalTag: "v2.0.0"},
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, normalizedTags)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	if vuln.GetId() != "GHSA-1234-5678-9012" {
		t.Errorf("expected ID GHSA-1234-5678-9012, got %s", vuln.GetId())
	}
	if vuln.GetSummary() != "Test vulnerability summary" {
		t.Errorf("expected summary, got %s", vuln.GetSummary())
	}
	if vuln.GetDetails() != desc {
		t.Errorf("expected details %q, got %q", desc, vuln.GetDetails())
	}

	// Verify aliases
	wantAliases := []string{"CVE-2026-99999"}
	if diff := cmp.Diff(wantAliases, vuln.GetAliases()); diff != "" {
		t.Errorf("Aliases mismatch (-want +got):\n%s", diff)
	}

	// Verify severity
	if len(vuln.GetSeverity()) != 2 {
		t.Fatalf("expected 2 severities, got %d", len(vuln.GetSeverity()))
	}
	if vuln.GetSeverity()[0].GetType() != osvschema.Severity_CVSS_V3 || vuln.GetSeverity()[0].GetScore() != v3Vector {
		t.Errorf("unexpected CVSS v3 severity: %+v", vuln.GetSeverity()[0])
	}
	if vuln.GetSeverity()[1].GetType() != osvschema.Severity_CVSS_V4 || vuln.GetSeverity()[1].GetScore() != v4Vector {
		t.Errorf("unexpected CVSS v4 severity: %+v", vuln.GetSeverity()[1])
	}

	// Verify affected
	if len(vuln.GetAffected()) != 1 {
		t.Fatalf("expected 1 affected item, got %d", len(vuln.GetAffected()))
	}
	aff := vuln.GetAffected()[0]
	if aff.GetPackage() != nil {
		t.Errorf("expected package to be nil, got: %+v", aff.GetPackage())
	}
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if r.GetType() != osvschema.Range_GIT || r.GetRepo() != "https://github.com/owner/repo" {
		t.Errorf("unexpected range type or repo: %+v", r)
	}
	if len(r.GetEvents()) != 2 {
		t.Fatalf("expected 2 events, got %d", len(r.GetEvents()))
	}
	if r.GetEvents()[0].GetIntroduced() != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("unexpected introduced: %s", r.GetEvents()[0].GetIntroduced())
	}
	// Verify range database_specific fields
	if r.GetDatabaseSpecific() == nil {
		t.Fatal("expected range database_specific to be non-nil")
	}
	rDbSpec := r.GetDatabaseSpecific().AsMap()
	if rDbSpec["source"] != string(models.VersionSourceAffected) {
		t.Errorf("expected range source %q, got %v", models.VersionSourceAffected, rDbSpec["source"])
	}
	eventsList, ok := rDbSpec["extracted_events"].([]any)
	if !ok || len(eventsList) != 2 {
		t.Fatalf("expected 2 extracted_events in range database_specific, got %v", rDbSpec["extracted_events"])
	}
	e0, _ := eventsList[0].(map[string]any)
	e1, _ := eventsList[1].(map[string]any)
	if e0["introduced"] != "1.0.0" {
		t.Errorf("expected extracted introduced 1.0.0, got %v", e0["introduced"])
	}
	if e1["fixed"] != "2.0.0" {
		t.Errorf("expected extracted fixed 2.0.0, got %v", e1["fixed"])
	}

	// Verify database_specific fields
	dbSpec := vuln.GetDatabaseSpecific().AsMap()
	if dbSpec["github_reviewed"] != false {
		t.Errorf("expected github_reviewed to be false, got %v", dbSpec["github_reviewed"])
	}
	if dbSpec["severity"] != "HIGH" {
		t.Errorf("expected severity HIGH, got %v", dbSpec["severity"])
	}
	cwesList, ok := dbSpec["cwe_ids"].([]any)
	if !ok || len(cwesList) != 2 {
		t.Errorf("expected 2 cwe_ids, got %v", dbSpec["cwe_ids"])
	}

	// Verify references
	refURLs := make(map[string]bool)
	for _, ref := range vuln.GetReferences() {
		refURLs[ref.GetUrl()] = true
	}
	if !refURLs["https://github.com/owner/repo/security/advisories/GHSA-1234-5678-9012"] {
		t.Errorf("missing advisory reference URL")
	}
	if !refURLs["https://github.com/owner/repo"] {
		t.Errorf("missing repo package reference URL")
	}
	if !refURLs["https://nvd.nist.gov/vuln/detail/CVE-2026-99999"] {
		t.Errorf("missing NVD reference URL")
	}
	if !refURLs["https://example.com/exploit"] {
		t.Errorf("missing extracted description reference URL")
	}
}

func TestConvertAdvisoryToOSV_NoVulnerabilities(t *testing.T) {
	t.Parallel()

	advisory := GHSAAdvisory{
		GHSAID:  "GHSA-novuln-test",
		Summary: "No vuln declared",
		State:   "published",
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "empty-vuln-repo",
		CanonicalURL: "https://github.com/owner/empty-vuln-repo",
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, nil)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	if len(vuln.GetAffected()) != 1 {
		t.Fatalf("expected 1 default affected item, got %d", len(vuln.GetAffected()))
	}

	aff := vuln.GetAffected()[0]
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if r.GetType() != osvschema.Range_GIT || r.GetRepo() != "https://github.com/owner/empty-vuln-repo" {
		t.Errorf("unexpected range type or repo: %+v", r)
	}
	if len(r.GetEvents()) != 1 || r.GetEvents()[0].GetIntroduced() != "0" {
		t.Errorf("unexpected events: %+v", r.GetEvents())
	}
}

func TestConvertAdvisoryToOSV_Withdrawn(t *testing.T) {
	t.Parallel()

	withdrawnTime := time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC)
	advisory := GHSAAdvisory{
		GHSAID:      "GHSA-withdrawn-test",
		Summary:     "Withdrawn test",
		State:       "withdrawn",
		WithdrawnAt: &withdrawnTime,
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, nil)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	if vuln.GetWithdrawn() == nil {
		t.Fatalf("expected withdrawn timestamp, got nil")
	}
	if !vuln.GetWithdrawn().AsTime().Equal(withdrawnTime) {
		t.Errorf("withdrawn timestamp mismatch: got %v, want %v", vuln.GetWithdrawn().AsTime(), withdrawnTime)
	}
}

func TestConvertAdvisoryToOSV_UnresolvedTagsFallback(t *testing.T) {
	t.Parallel()

	vRange := "< 2.0.0"
	pkgName := "lib-unresolved"
	advisory := GHSAAdvisory{
		GHSAID:  "GHSA-unresolved-tags",
		Summary: "Unresolved tags fallback",
		State:   "published",
		Vulnerabilities: []GHSAVulnerability{
			{
				Package: &GHSAPackage{
					Ecosystem: "Go",
					Name:      &pkgName,
				},
				VulnerableVersionRange: &vRange,
			},
		},
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	// Empty normalized tags (e.g. tag not matched)
	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, map[string]git.NormalizedTag{})
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	if len(vuln.GetAffected()) != 1 {
		t.Fatalf("expected 1 affected item, got %d", len(vuln.GetAffected()))
	}
	aff := vuln.GetAffected()[0]
	if aff.GetPackage() != nil {
		t.Errorf("expected package to be nil, got: %+v", aff.GetPackage())
	}
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 fallback range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if r.GetType() != osvschema.Range_GIT || r.GetRepo() != "https://github.com/owner/repo" {
		t.Errorf("expected Range_GIT fallback with repo, got type %v repo %q", r.GetType(), r.GetRepo())
	}
	if len(r.GetEvents()) != 1 || r.GetEvents()[0].GetIntroduced() != "0" {
		t.Errorf("unexpected fallback events: %+v", r.GetEvents())
	}
	if r.GetDatabaseSpecific() == nil {
		t.Fatal("expected fallback range database_specific to be non-nil")
	}
	fallbackDbSpec := r.GetDatabaseSpecific().AsMap()
	if fallbackDbSpec["source"] != string(models.VersionSourceAffected) {
		t.Errorf("expected source %q, got %v", models.VersionSourceAffected, fallbackDbSpec["source"])
	}
	fallbackEvents, ok := fallbackDbSpec["extracted_events"].([]any)
	if !ok || len(fallbackEvents) != 2 {
		t.Fatalf("expected 2 fallback extracted_events, got %v", fallbackDbSpec["extracted_events"])
	}

	rootDbSpec := vuln.GetDatabaseSpecific().AsMap()
	unresolved, ok := rootDbSpec["unresolved_ranges"].([]any)
	if !ok || len(unresolved) != 1 {
		t.Fatalf("expected 1 unresolved_ranges entry in root database_specific, got %v", rootDbSpec["unresolved_ranges"])
	}
	ur0, _ := unresolved[0].(map[string]any)
	if ur0["source"] != string(models.VersionSourceAffected) {
		t.Errorf("expected unresolved_ranges source %q, got %v", models.VersionSourceAffected, ur0["source"])
	}
}

func TestWriteOSVRecord(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	vuln := &vulns.Vulnerability{
		Vulnerability: &osvschema.Vulnerability{
			Id:      "GHSA-write-test",
			Summary: "Write test",
		},
	}

	err := writeOSVRecord(vuln, tmpDir, nil, "")
	if err != nil {
		t.Fatalf("writeOSVRecord failed: %v", err)
	}

	outPath := filepath.Join(tmpDir, "GHSA-write-test.json")
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("expected output file to exist: %v", err)
	}
	if !strings.Contains(string(data), "GHSA-write-test") {
		t.Errorf("output file content does not contain vulnerability ID: %s", string(data))
	}

	// Test empty vuln ID returns error
	emptyVuln := &vulns.Vulnerability{
		Vulnerability: &osvschema.Vulnerability{},
	}
	err = writeOSVRecord(emptyVuln, tmpDir, nil, "")
	if err == nil {
		t.Errorf("expected error for empty vuln ID, got nil")
	}
}

func TestConvertAdvisoryToOSV_EmptyID(t *testing.T) {
	t.Parallel()

	advisory := GHSAAdvisory{
		Summary: "Missing ID",
	}

	repoTarget := RepoTarget{
		Owner: "owner",
		Repo:  "repo",
	}

	_, err := ConvertAdvisoryToOSV(advisory, repoTarget, nil)
	if err == nil {
		t.Errorf("expected error for empty GHSA ID, got nil")
	}
}

func TestConvertAdvisoryToOSV_MultipleVulnerabilities(t *testing.T) {
	t.Parallel()

	vRange1 := "< 1.0.0"
	vRange2 := ">= 2.0.0, < 2.5.0"
	pkg1 := "pkg-one"
	pkg2 := "pkg-two"

	advisory := GHSAAdvisory{
		GHSAID:  "GHSA-multi-vuln",
		Summary: "Multiple vulnerabilities in advisory",
		State:   "published",
		Vulnerabilities: []GHSAVulnerability{
			{
				Package: &GHSAPackage{
					Ecosystem: "npm",
					Name:      &pkg1,
				},
				VulnerableVersionRange: &vRange1,
			},
			{
				Package: &GHSAPackage{
					Ecosystem: "Go",
					Name:      &pkg2,
				},
				VulnerableVersionRange: &vRange2,
			},
		},
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	normalizedTags := map[string]git.NormalizedTag{
		"1-0-0": {Commit: "1111111111111111111111111111111111111111", OriginalTag: "v1.0.0"},
		"2-0-0": {Commit: "2222222222222222222222222222222222222222", OriginalTag: "v2.0.0"},
		"2-5-0": {Commit: "2525252525252525252525252525252525252525", OriginalTag: "v2.5.0"},
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, normalizedTags)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	// Must have exactly 1 Affected entry with nil Package
	if len(vuln.GetAffected()) != 1 {
		t.Fatalf("expected 1 aggregated affected entry, got %d", len(vuln.GetAffected()))
	}
	aff := vuln.GetAffected()[0]
	if aff.GetPackage() != nil {
		t.Errorf("expected package to be nil, got: %+v", aff.GetPackage())
	}

	// Must have 2 GIT ranges
	if len(aff.GetRanges()) != 2 {
		t.Fatalf("expected 2 GIT ranges, got %d", len(aff.GetRanges()))
	}
	for i, r := range aff.GetRanges() {
		if r.GetType() != osvschema.Range_GIT || r.GetRepo() != "https://github.com/owner/repo" {
			t.Errorf("range[%d] unexpected type %v or repo %q", i, r.GetType(), r.GetRepo())
		}
		if r.GetDatabaseSpecific() == nil {
			t.Errorf("range[%d] expected database_specific to be non-nil", i)
		} else {
			dbSpec := r.GetDatabaseSpecific().AsMap()
			if dbSpec["source"] != string(models.VersionSourceAffected) {
				t.Errorf("range[%d] expected source %q, got %v", i, models.VersionSourceAffected, dbSpec["source"])
			}
			if _, ok := dbSpec["extracted_events"].([]any); !ok {
				t.Errorf("range[%d] missing extracted_events in database_specific", i)
			}
		}
	}
}

func TestConvertAdvisoryToOSV_GroupingExtractedEvents(t *testing.T) {
	t.Parallel()

	vRange1 := "< 1.5.0"
	vRange2 := "< 2.0.0"

	advisory := GHSAAdvisory{
		GHSAID:  "GHSA-grouping-test",
		Summary: "Grouping test with common introduced commit",
		State:   "published",
		Vulnerabilities: []GHSAVulnerability{
			{
				VulnerableVersionRange: &vRange1,
			},
			{
				VulnerableVersionRange: &vRange2,
			},
		},
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	normalizedTags := map[string]git.NormalizedTag{
		"1-5-0": {Commit: "1515151515151515151515151515151515151515", OriginalTag: "v1.5.0"},
		"2-0-0": {Commit: "2020202020202020202020202020202020202020", OriginalTag: "v2.0.0"},
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, normalizedTags)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	if len(vuln.GetAffected()) != 1 {
		t.Fatalf("expected 1 affected item, got %d", len(vuln.GetAffected()))
	}
	aff := vuln.GetAffected()[0]

	// Since both ranges have introduced "0", GroupAffectedRanges groups them into 1 range with multiple fixed events
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 grouped range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if len(r.GetEvents()) != 3 {
		t.Fatalf("expected 3 events (1 introduced + 2 fixed), got %d", len(r.GetEvents()))
	}

	// Verify merged database_specific
	if r.GetDatabaseSpecific() == nil {
		t.Fatal("expected database_specific to be present on grouped range")
	}
	dbSpec := r.GetDatabaseSpecific().AsMap()
	if dbSpec["source"] != string(models.VersionSourceAffected) {
		t.Errorf("expected source %q, got %v", models.VersionSourceAffected, dbSpec["source"])
	}
	extracted, ok := dbSpec["extracted_events"].([]any)
	if !ok {
		t.Fatalf("expected extracted_events in grouped range database_specific, got %v", dbSpec["extracted_events"])
	}
	// Merged extracted_events should contain introduced "0", fixed "1.5.0", and fixed "2.0.0" (deduplicated)
	if len(extracted) != 3 {
		t.Errorf("expected 3 merged extracted_events, got %d: %v", len(extracted), extracted)
	}
}

func TestConvertAdvisoryToOSV_PartialResolution(t *testing.T) {
	t.Parallel()

	vRange1 := ">= 1.0.0, < 2.0.0"
	vRange2 := "< 99.0.0" // non-existent tag

	advisory := GHSAAdvisory{
		GHSAID:  "GHSA-partial-resolution",
		Summary: "Partial resolution test",
		State:   "published",
		Vulnerabilities: []GHSAVulnerability{
			{
				VulnerableVersionRange: &vRange1,
			},
			{
				VulnerableVersionRange: &vRange2,
			},
		},
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	normalizedTags := map[string]git.NormalizedTag{
		"1-0-0": {Commit: "1111111111111111111111111111111111111111", OriginalTag: "v1.0.0"},
		"2-0-0": {Commit: "2222222222222222222222222222222222222222", OriginalTag: "v2.0.0"},
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, normalizedTags)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	aff := vuln.GetAffected()[0]
	// Range 1 resolved successfully
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 resolved range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if len(r.GetEvents()) != 2 {
		t.Errorf("expected 2 events in resolved range, got %d", len(r.GetEvents()))
	}

	// Range 2 could not be resolved, so it must be present in top-level unresolved_ranges
	rootDbSpec := vuln.GetDatabaseSpecific().AsMap()
	unresolved, ok := rootDbSpec["unresolved_ranges"].([]any)
	if !ok || len(unresolved) != 1 {
		t.Fatalf("expected 1 unresolved range in root database_specific, got %v", rootDbSpec["unresolved_ranges"])
	}
	ur0, _ := unresolved[0].(map[string]any)
	if ur0["source"] != string(models.VersionSourceAffected) {
		t.Errorf("expected source %q, got %v", models.VersionSourceAffected, ur0["source"])
	}
	urEvents, ok := ur0["extracted_events"].([]any)
	if !ok || len(urEvents) != 2 {
		t.Fatalf("expected 2 extracted_events in unresolved range, got %v", ur0["extracted_events"])
	}
}

func TestConvertAdvisoryToOSV_ExactVersion(t *testing.T) {
	t.Parallel()

	vRange := "= 1.0.0"

	advisory := GHSAAdvisory{
		GHSAID:  "GHSA-exact-version-test",
		Summary: "Exact version test",
		State:   "published",
		Vulnerabilities: []GHSAVulnerability{
			{
				VulnerableVersionRange: &vRange,
			},
		},
	}

	repoTarget := RepoTarget{
		Owner:        "owner",
		Repo:         "repo",
		CanonicalURL: "https://github.com/owner/repo",
	}

	normalizedTags := map[string]git.NormalizedTag{
		"1-0-0": {Commit: "1111111111111111111111111111111111111111", OriginalTag: "v1.0.0"},
	}

	vuln, err := ConvertAdvisoryToOSV(advisory, repoTarget, normalizedTags)
	if err != nil {
		t.Fatalf("ConvertAdvisoryToOSV failed: %v", err)
	}

	aff := vuln.GetAffected()[0]
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if len(r.GetEvents()) != 2 {
		t.Fatalf("expected 2 events (introduced + last_affected), got %d", len(r.GetEvents()))
	}
	if r.GetEvents()[0].GetIntroduced() != "1111111111111111111111111111111111111111" {
		t.Errorf("unexpected introduced commit: %s", r.GetEvents()[0].GetIntroduced())
	}
	if r.GetEvents()[1].GetLastAffected() != "1111111111111111111111111111111111111111" {
		t.Errorf("unexpected last_affected commit: %s", r.GetEvents()[1].GetLastAffected())
	}

	dbSpec := r.GetDatabaseSpecific().AsMap()
	if dbSpec["source"] != string(models.VersionSourceAffected) {
		t.Errorf("expected source %q, got %v", models.VersionSourceAffected, dbSpec["source"])
	}
	extracted, ok := dbSpec["extracted_events"].([]any)
	if !ok || len(extracted) != 2 {
		t.Fatalf("expected 2 extracted events, got %v", dbSpec["extracted_events"])
	}
}
