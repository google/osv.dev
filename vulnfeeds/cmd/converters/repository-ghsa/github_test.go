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
	"sync/atomic"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseRepoTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		input       string
		wantTarget  RepoTarget
		expectError bool
	}{
		{
			name:  "standard owner/repo",
			input: "google/osv.dev",
			wantTarget: RepoTarget{
				Owner:        "google",
				Repo:         "osv.dev",
				CanonicalURL: "https://github.com/google/osv.dev",
			},
		},
		{
			name:  "https URL",
			input: "https://github.com/gin-gonic/gin",
			wantTarget: RepoTarget{
				Owner:        "gin-gonic",
				Repo:         "gin",
				CanonicalURL: "https://github.com/gin-gonic/gin",
			},
		},
		{
			name:  "https URL with trailing slash",
			input: "https://github.com/gin-gonic/gin/",
			wantTarget: RepoTarget{
				Owner:        "gin-gonic",
				Repo:         "gin",
				CanonicalURL: "https://github.com/gin-gonic/gin",
			},
		},
		{
			name:  "https URL with .git",
			input: "https://github.com/gin-gonic/gin.git",
			wantTarget: RepoTarget{
				Owner:        "gin-gonic",
				Repo:         "gin",
				CanonicalURL: "https://github.com/gin-gonic/gin",
			},
		},
		{
			name:  "http URL",
			input: "http://github.com/foo/bar",
			wantTarget: RepoTarget{
				Owner:        "foo",
				Repo:         "bar",
				CanonicalURL: "https://github.com/foo/bar",
			},
		},
		{
			name:  "github.com prefix without scheme",
			input: "github.com/foo/bar",
			wantTarget: RepoTarget{
				Owner:        "foo",
				Repo:         "bar",
				CanonicalURL: "https://github.com/foo/bar",
			},
		},
		{
			name:  "SSH git@github.com format",
			input: "git@github.com:torvalds/linux.git",
			wantTarget: RepoTarget{
				Owner:        "torvalds",
				Repo:         "linux",
				CanonicalURL: "https://github.com/torvalds/linux",
			},
		},
		{
			name:  "with leading and trailing whitespace",
			input: "   owner/repo   ",
			wantTarget: RepoTarget{
				Owner:        "owner",
				Repo:         "repo",
				CanonicalURL: "https://github.com/owner/repo",
			},
		},
		{
			name:  "owner and repo with spaces",
			input: "  owner / repo  ",
			wantTarget: RepoTarget{
				Owner:        "owner",
				Repo:         "repo",
				CanonicalURL: "https://github.com/owner/repo",
			},
		},
		{
			name:  "repo with trailing slash and .git",
			input: "https://github.com/owner/repo.git/",
			wantTarget: RepoTarget{
				Owner:        "owner",
				Repo:         "repo",
				CanonicalURL: "https://github.com/owner/repo",
			},
		},
		{
			name:        "empty string",
			input:       "",
			expectError: true,
		},
		{
			name:        "single name without slash",
			input:       "justrepo",
			expectError: true,
		},
		{
			name:        "only owner with trailing slash",
			input:       "owner/",
			expectError: true,
		},
		{
			name:        "empty owner",
			input:       "/repo",
			expectError: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParseRepoTarget(tc.input)
			if tc.expectError {
				if err == nil {
					t.Fatalf("ParseRepoTarget(%q) expected error, got nil", tc.input)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseRepoTarget(%q) unexpected error: %v", tc.input, err)
			}

			if diff := cmp.Diff(tc.wantTarget, got); diff != "" {
				t.Errorf("ParseRepoTarget(%q) mismatch (-want +got):\n%s", tc.input, diff)
			}
		})
	}
}

func TestParseNextLink(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   string
	}{
		{
			name:   "standard next and last links",
			header: `<https://api.github.com/repositories/123/security-advisories?after=Y3Vyc29yOjE%3D>; rel="next", <https://api.github.com/repositories/123/security-advisories?after=Y3Vyc29yOjEw%3D>; rel="last"`,
			want:   "https://api.github.com/repositories/123/security-advisories?after=Y3Vyc29yOjE%3D",
		},
		{
			name:   "only next link",
			header: `<https://api.github.com/repositories/123/security-advisories?after=next>; rel="next"`,
			want:   "https://api.github.com/repositories/123/security-advisories?after=next",
		},
		{
			name:   "no next link (prev and first only)",
			header: `<https://api.github.com/repositories/123/security-advisories?before=prev>; rel="prev", <https://api.github.com/repositories/123/security-advisories?first>; rel="first"`,
			want:   "",
		},
		{
			name:   "unquoted rel=next",
			header: `<https://api.github.com/repositories/123/security-advisories?after=unquoted>; rel=next`,
			want:   "https://api.github.com/repositories/123/security-advisories?after=unquoted",
		},
		{
			name:   "single quoted rel='next'",
			header: `<https://api.github.com/repositories/123/security-advisories?after=single>; rel='next'`,
			want:   "https://api.github.com/repositories/123/security-advisories?after=single",
		},
		{
			name:   "empty header",
			header: "",
			want:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseNextLink(tc.header)
			if got != tc.want {
				t.Errorf("parseNextLink(%q) = %q; want %q", tc.header, got, tc.want)
			}
		})
	}
}

func TestGitHubClient_FetchAdvisories_Pagination(t *testing.T) {
	t.Parallel()

	page1Advisories := []GHSAAdvisory{
		{GHSAID: "GHSA-1111-1111-1111", Summary: "Advisory 1"},
	}
	page2Advisories := []GHSAAdvisory{
		{GHSAID: "GHSA-2222-2222-2222", Summary: "Advisory 2"},
	}

	var serverURL string
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify expected headers
		if auth := r.Header.Get("Authorization"); auth != "Bearer test-token-123" {
			t.Errorf("expected Bearer token, got %q", auth)
		}
		if r.Header.Get("Accept") != "application/vnd.github+json" {
			t.Errorf("expected Accept header for github+json, got %q", r.Header.Get("Accept"))
		}
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("expected API version header, got %q", r.Header.Get("X-GitHub-Api-Version"))
		}

		cursor := r.URL.Query().Get("after")
		w.Header().Set("Content-Type", "application/json")

		if cursor == "" {
			// Page 1: return page1 and next link
			w.Header().Set("Link", `<`+serverURL+`/repos/test-owner/test-repo/security-advisories?per_page=100&after=page2cursor>; rel="next"`)
			_ = json.NewEncoder(w).Encode(page1Advisories)
		} else if cursor == "page2cursor" {
			// Page 2: return page2 without next link
			_ = json.NewEncoder(w).Encode(page2Advisories)
		} else {
			http.NotFound(w, r)
		}
	}))
	defer ts.Close()
	serverURL = ts.URL

	client := NewGitHubClient("test-token-123", ts.Client())
	client.SetBaseURL(ts.URL)

	advisories, err := client.FetchAdvisories(context.Background(), "test-owner", "test-repo", "published")
	if err != nil {
		t.Fatalf("FetchAdvisories failed: %v", err)
	}

	if len(advisories) != 2 {
		t.Fatalf("FetchAdvisories returned %d advisories; want 2", len(advisories))
	}
	if advisories[0].GHSAID != "GHSA-1111-1111-1111" || advisories[1].GHSAID != "GHSA-2222-2222-2222" {
		t.Errorf("Unexpected advisories fetched: %+v", advisories)
	}
}

func TestGitHubClient_FetchAdvisories_NotFound(t *testing.T) {
	t.Parallel()

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()

	client := NewGitHubClient("", ts.Client())
	client.SetBaseURL(ts.URL)

	advisories, err := client.FetchAdvisories(context.Background(), "owner", "notfound", "all")
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if len(advisories) != 0 {
		t.Errorf("expected 0 advisories on 404, got %d", len(advisories))
	}
}

func TestGitHubClient_FetchAdvisories_RetryOn429(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if attempts.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"message": "rate limit exceeded"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode([]GHSAAdvisory{
			{GHSAID: "GHSA-recovered", Summary: "Recovered"},
		})
	}))
	defer ts.Close()

	client := NewGitHubClient("", ts.Client())
	client.SetBaseURL(ts.URL)

	advisories, err := client.FetchAdvisories(context.Background(), "owner", "retry-repo", "published")
	if err != nil {
		t.Fatalf("FetchAdvisories failed after retry: %v", err)
	}
	if len(advisories) != 1 || advisories[0].GHSAID != "GHSA-recovered" {
		t.Errorf("Unexpected advisories after retry: %+v", advisories)
	}
	if attempts.Load() < 2 {
		t.Errorf("Expected at least 2 attempts, got %d", attempts.Load())
	}
}

func TestCollectRepos(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "repos.txt")
	fileContent := "# Comment\nrepo/from-file-1\n\nrepo/from-file-2\n# Another comment\nrepo/from-csv-1\n"
	if err := os.WriteFile(filePath, []byte(fileContent), 0644); err != nil {
		t.Fatalf("Failed writing temp repos file: %v", err)
	}

	reposCSV := "repo/from-csv-1, repo/from-csv-2"
	positional := []string{"repo/positional", "repo/from-file-1"}

	repos, err := collectRepos(reposCSV, filePath, positional)
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

	// Test non-existent file returns error
	_, err = collectRepos("", filepath.Join(tmpDir, "does-not-exist.txt"), nil)
	if err == nil {
		t.Errorf("collectRepos with non-existent file expected error, got nil")
	}
}
