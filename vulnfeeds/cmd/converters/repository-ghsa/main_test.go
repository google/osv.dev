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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/vulns"
)

func TestProcessRepository_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	origOutDir := *outDirFlag
	origState := *stateFlag
	*outDirFlag = tmpDir
	*stateFlag = "published"
	defer func() {
		*outDirFlag = origOutDir
		*stateFlag = origState
	}()

	cveID := "CVE-2026-8888"
	desc := "End to end test advisory"
	pkgName := "e2e-pkg"
	vRange := ">= 1.0.0, < 2.0.0"
	pubTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

	advisories := []GHSAAdvisory{
		{
			GHSAID:      "GHSA-e2e-test-1234",
			CVEID:       &cveID,
			HTMLURL:     "https://github.com/test-owner/test-repo/security/advisories/GHSA-e2e-test-1234",
			Summary:     "E2E Advisory",
			Description: &desc,
			State:       "published",
			PublishedAt: &pubTime,
			Vulnerabilities: []GHSAVulnerability{
				{
					Package: &GHSAPackage{
						Ecosystem: "npm",
						Name:      &pkgName,
					},
					VulnerableVersionRange: &vRange,
				},
			},
		},
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(advisories)
	}))
	defer ts.Close()

	ghClient := NewGitHubClient("", ts.Client())
	ghClient.SetBaseURL(ts.URL)

	target := RepoTarget{
		Owner:        "test-owner",
		Repo:         "test-repo",
		CanonicalURL: "https://github.com/test-owner/test-repo",
	}

	tagsCache := git.NewRepoTagsCache()
	tagsCache.Set(target.CanonicalURL, git.RepoTagsMap{
		NormalizedTag: map[string]git.NormalizedTag{
			"1-0-0": {Commit: "1111111111111111111111111111111111111111", OriginalTag: "v1.0.0"},
			"2-0-0": {Commit: "2222222222222222222222222222222222222222", OriginalTag: "v2.0.0"},
		},
	})

	count, err := processRepository(context.Background(), target, ghClient, tagsCache, ts.Client(), nil)
	if err != nil {
		t.Fatalf("processRepository failed: %v", err)
	}
	if count != 1 {
		t.Errorf("processRepository converted %d advisories; want 1", count)
	}

	// Verify output record
	recordPath := filepath.Join(tmpDir, "GHSA-e2e-test-1234.json")
	data, err := os.ReadFile(recordPath)
	if err != nil {
		t.Fatalf("expected output file %s: %v", recordPath, err)
	}

	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatalf("failed unmarshaling generated OSV JSON: %v", err)
	}

	if parsed["id"] != "GHSA-e2e-test-1234" {
		t.Errorf("expected ID GHSA-e2e-test-1234, got %v", parsed["id"])
	}
	if parsed["summary"] != "E2E Advisory" {
		t.Errorf("expected summary E2E Advisory, got %v", parsed["summary"])
	}

	affectedList, ok := parsed["affected"].([]any)
	if !ok || len(affectedList) == 0 {
		t.Fatalf("expected affected list in generated JSON, got: %v", parsed["affected"])
	}
	for i, aff := range affectedList {
		affMap, ok := aff.(map[string]any)
		if !ok {
			t.Fatalf("affected[%d] is not a map: %v", i, aff)
		}
		if pkg, exists := affMap["package"]; exists {
			t.Errorf("affected[%d] has unexpected 'package' field: %v", i, pkg)
		}
		rangesList, ok := affMap["ranges"].([]any)
		if !ok || len(rangesList) == 0 {
			t.Fatalf("affected[%d] missing ranges: %v", i, affMap)
		}
		for j, r := range rangesList {
			rMap, ok := r.(map[string]any)
			if !ok {
				t.Fatalf("affected[%d].ranges[%d] is not a map: %v", i, j, r)
			}
			if rMap["type"] != "GIT" {
				t.Errorf("affected[%d].ranges[%d] type = %v, want GIT", i, j, rMap["type"])
			}
			dbSpec, ok := rMap["database_specific"].(map[string]any)
			if !ok {
				t.Fatalf("affected[%d].ranges[%d] missing database_specific: %v", i, j, rMap)
			}
			if dbSpec["source"] != "AFFECTED_FIELD" {
				t.Errorf("affected[%d].ranges[%d] database_specific source = %v, want AFFECTED_FIELD", i, j, dbSpec["source"])
			}
			extracted, ok := dbSpec["extracted_events"].([]any)
			if !ok || len(extracted) == 0 {
				t.Fatalf("affected[%d].ranges[%d] database_specific missing extracted_events: %v", i, j, dbSpec)
			}
		}
	}
}

func TestProcessRepository_EmptyAdvisories(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]GHSAAdvisory{})
	}))
	defer ts.Close()

	ghClient := NewGitHubClient("", ts.Client())
	ghClient.SetBaseURL(ts.URL)

	target := RepoTarget{
		Owner:        "owner",
		Repo:         "empty",
		CanonicalURL: "https://github.com/owner/empty",
	}

	tagsCache := git.NewRepoTagsCache()
	count, err := processRepository(context.Background(), target, ghClient, tagsCache, ts.Client(), nil)
	if err != nil {
		t.Fatalf("processRepository unexpectedly failed on empty advisories: %v", err)
	}
	if count != 0 {
		t.Errorf("expected 0 converted advisories, got %d", count)
	}
}

func TestParseRepoFile_Formats(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr bool
	}{
		{
			name:  "json string array",
			input: `["google/osv.dev", "https://github.com/torvalds/linux", "pallets/flask"]`,
			want:  []string{"google/osv.dev", "https://github.com/torvalds/linux", "pallets/flask"},
		},
		{
			name:  "json object array with repo and url keys",
			input: `[{"repo": "google/osv.dev"}, {"url": "https://github.com/golang/go"}, {"name": "gin-gonic/gin"}]`,
			want:  []string{"google/osv.dev", "https://github.com/golang/go", "gin-gonic/gin"},
		},
		{
			name:  "json dict with repos list wrapper",
			input: `{"repos": ["google/osv.dev", "facebook/react"]}`,
			want:  []string{"google/osv.dev", "facebook/react"},
		},
		{
			name:  "json dict with repositories object list wrapper",
			input: `{"repositories": [{"repo": "google/osv.dev"}, {"url": "expressjs/express"}]}`,
			want:  []string{"google/osv.dev", "expressjs/express"},
		},
		{
			name:  "json map where keys are repositories",
			input: `{"google/osv.dev": {"active": true}, "gin-gonic/gin": {"active": false}}`,
			want:  []string{"gin-gonic/gin", "google/osv.dev"},
		},
		{
			name: "plain text with comments and empty lines",
			input: `
# Core repositories
google/osv.dev
https://github.com/torvalds/linux

# Another one
pallets/flask
`,
			want: []string{"google/osv.dev", "https://github.com/torvalds/linux", "pallets/flask"},
		},
		{
			name:  "empty input",
			input: "",
			want:  nil,
		},
		{
			name:  "whitespace only",
			input: "   \n\t\n  ",
			want:  nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseRepoFile([]byte(tc.input))
			if (err != nil) != tc.wantErr {
				t.Fatalf("parseRepoFile() err = %v, wantErr = %v", err, tc.wantErr)
			}
			// For map keys, order may vary; sort for comparison if needed
			if tc.name == "json map where keys are repositories" {
				if len(got) != len(tc.want) {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
				for _, w := range tc.want {
					if !slices.Contains(got, w) {
						t.Errorf("missing expected repo %s in %v", w, got)
					}
				}

				return
			}
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("parseRepoFile mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestReadRepoFile_Local(t *testing.T) {
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "repos.json")
	content := `["google/osv.dev", "golang/go"]`
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		t.Fatalf("failed writing test file: %v", err)
	}

	ctx := context.Background()
	repos, err := readRepoFile(ctx, filePath, nil)
	if err != nil {
		t.Fatalf("readRepoFile failed: %v", err)
	}

	want := []string{"google/osv.dev", "golang/go"}
	if diff := cmp.Diff(want, repos); diff != "" {
		t.Errorf("readRepoFile mismatch (-want +got):\n%s", diff)
	}
}

func TestReadRepoFile_InvalidGCSPath(t *testing.T) {
	ctx := context.Background()
	// Malformed gs:// without object
	_, err := readRepoFile(ctx, "gs://onlybucket", nil)
	if err == nil {
		t.Error("expected error for malformed GCS URI, got nil")
	}

	// Empty object
	_, err = readRepoFile(ctx, "gs://bucket/", nil)
	if err == nil {
		t.Error("expected error for empty GCS object path, got nil")
	}
}

func TestCollectRepos_Integration(t *testing.T) {
	tmpDir := t.TempDir()
	localFile := filepath.Join(tmpDir, "repos.txt")
	if err := os.WriteFile(localFile, []byte("repo/from-file-1\nrepo/from-file-2\n"), 0644); err != nil {
		t.Fatalf("failed writing local file: %v", err)
	}

	ctx := context.Background()
	repos, err := collectRepos(ctx, "repo/from-csv-1, repo/from-csv-2", localFile, "", []string{"repo/positional", "repo/from-csv-1"}, nil)
	if err != nil {
		t.Fatalf("collectRepos failed: %v", err)
	}

	want := []string{
		"repo/from-csv-1",
		"repo/from-csv-2",
		"repo/from-file-1",
		"repo/from-file-2",
		"repo/positional",
	}

	if diff := cmp.Diff(want, repos); diff != "" {
		t.Errorf("collectRepos mismatch (-want +got):\n%s", diff)
	}
}

func TestWriteOSVRecord_EmptyID(t *testing.T) {
	vuln := &vulns.Vulnerability{}
	err := writeOSVRecord(vuln, "", nil, "")
	if err == nil {
		t.Error("expected error for empty vuln ID, got nil")
	}
}

func TestExtractRepoFromMap_Keys(t *testing.T) {
	tests := []struct {
		input map[string]any
		want  string
	}{
		{input: map[string]any{"canonical_url": "https://github.com/org/repo"}, want: "https://github.com/org/repo"},
		{input: map[string]any{"git": "git@github.com:org/repo.git"}, want: "git@github.com:org/repo.git"},
		{input: map[string]any{"other": "value"}, want: ""},
		{input: map[string]any{"repo": 123}, want: ""},
	}

	for _, tc := range tests {
		got := extractRepoFromMap(tc.input)
		if got != tc.want {
			t.Errorf("extractRepoFromMap(%v) = %q, want %q", tc.input, got, tc.want)
		}
	}
}
