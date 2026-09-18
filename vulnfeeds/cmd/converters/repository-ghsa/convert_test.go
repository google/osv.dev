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

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "1111111111111111111111111111111111111111"},
				{Fixed: "2222222222222222222222222222222222222222"},
			},
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

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "0"},
				{Fixed: "2222222222222222222222222222222222222222"},
			},
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

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "0"},
				{LastAffected: "1111111111111111111111111111111111111111"},
			},
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

		want := &osvschema.Range{
			Type: osvschema.Range_GIT,
			Repo: repoURL,
			Events: []*osvschema.Event{
				{Introduced: "1111111111111111111111111111111111111111"},
			},
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
	if aff.GetPackage().GetName() != "my-awesome-lib" || aff.GetPackage().GetEcosystem() != "npm" {
		t.Errorf("unexpected package: %+v", aff.GetPackage())
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
	if r.GetEvents()[1].GetFixed() != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("unexpected fixed: %s", r.GetEvents()[1].GetFixed())
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
	if len(aff.GetRanges()) != 1 {
		t.Fatalf("expected 1 fallback range, got %d", len(aff.GetRanges()))
	}
	r := aff.GetRanges()[0]
	if r.GetType() != osvschema.Range_ECOSYSTEM {
		t.Errorf("expected Range_ECOSYSTEM fallback, got %v", r.GetType())
	}
	if len(r.GetEvents()) != 2 || r.GetEvents()[0].GetIntroduced() != "0" || r.GetEvents()[1].GetFixed() != "2.0.0" {
		t.Errorf("unexpected fallback events: %+v", r.GetEvents())
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
