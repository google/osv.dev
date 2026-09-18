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
	"testing"
	"time"

	"github.com/google/osv.dev/vulnfeeds/git"
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

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
}

func TestProcessRepository_EmptyAdvisories(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
