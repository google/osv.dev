package main

import (
	"bytes"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"google.golang.org/protobuf/proto"
)

func TestGetRepoDirName(t *testing.T) {
	tests := []struct {
		url          string
		expectedBase string
	}{
		{"https://github.com/google/osv.dev.git", "osv.dev"},
		{"https://github.com/google/osv.dev", "osv.dev"},
		{"https://gitlab.com/gitlab-org/gitlab.git", "gitlab"},
	}

	for _, tt := range tests {
		result := getRepoDirName(tt.url)
		// We can't predict the hash easily in a hardcoded string without re-implementing logic,
		// but we can check the prefix.
		if len(result) <= len(tt.expectedBase) {
			t.Errorf("expected result to be longer than base name, got %s", result)
		}
		if result[:len(tt.expectedBase)] != tt.expectedBase {
			t.Errorf("expected result to start with %s, got %s", tt.expectedBase, result)
		}
	}
}

func TestPrepareURL(t *testing.T) {
	tests := []struct {
		name      string
		url       string
		expected  string
		expectErr bool
	}{
		{
			name:      "Normal https protocol",
			url:       "https://github.com/google/osv.dev.git",
			expected:  "https://github.com/google/osv.dev.git",
			expectErr: false,
		},
		{
			name:      "GitHub http protocol",
			url:       "http://github.com/google/osv.dev",
			expected:  "http://github.com/google/osv.dev",
			expectErr: false,
		},
		{
			name:      "GitHub git protocol, change to https",
			url:       "git://github.com/google/osv.dev.git",
			expected:  "https://github.com/google/osv.dev.git",
			expectErr: false,
		},
		{
			name:      "Non-github git protocol, no change",
			url:       "git://code.qt.io/qt/qt5.git",
			expected:  "git://code.qt.io/qt/qt5.git",
			expectErr: false,
		},
		{
			name:      "Non github url",
			url:       "https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git",
			expected:  "https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux.git",
			expectErr: false,
		},
		{
			name:      "URL with query parameters",
			url:       "https://github.com/google/osv.dev.git?q=value",
			expected:  "https://github.com/google/osv.dev.git",
			expectErr: false,
		},
		{
			name:      "URL with fragment",
			url:       "https://github.com/lxml/lxml#diff-59130575b4fb2932c957db2922977d7d89afb0b2085357db1a14615a2fcad776",
			expected:  "https://github.com/lxml/lxml",
			expectErr: false,
		},
		{
			name:      "Empty URL",
			url:       "",
			expected:  "",
			expectErr: true,
		},
		{
			name:      "Unsupported protocol file://",
			url:       "file://this-is-invalid",
			expected:  "",
			expectErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			result, err := prepareURL(req, tt.url)
			if tt.expectErr {
				if err == nil {
					t.Errorf("prepareURL() expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("prepareURL() unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("prepareURL() = %s, expected %s", result, tt.expected)
				}
			}
		})
	}
}

//nolint:revive // These error strings are testing for output from git
func TestIsAuthError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: Authentication failed for 'https://github.com/google/this-repo-does-not-exist-12345.git/'"), true},
		{errors.New("remote: Repository not found."), true},
		{errors.New("fatal: could not read Username for 'https://github.com': terminal prompts disabled"), true},
		{errors.New("some other error"), false},
		{errors.New("git clone failed: exit status 128"), false},
	}

	for _, tt := range tests {
		if result := isAuthError(tt.err); result != tt.expected {
			t.Errorf("isAuthError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsIndexLockError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: Unable to create '/path/to/repo.git/index.lock': File exists"), true},
		{errors.New("some other error"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isIndexLockError(tt.err); result != tt.expected {
			t.Errorf("isIndexLockError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRefConflictError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("error: some local refs could not be updated; try running 'git remote prune origin' to remove any old, conflicting branches"), true},
		{errors.New("error: fetching ref refs/remotes/some-ref-name failed: refname conflict"), true},
		{errors.New("some other error"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRefConflictError(tt.err); result != tt.expected {
			t.Errorf("isRefConflictError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestGitHandler_InvalidURL(t *testing.T) {
	tests := []struct {
		url          string
		expectedCode int
	}{
		{"", http.StatusBadRequest},
		{"ftp://example.com/repo.git", http.StatusBadRequest}, // ftp is not allowed (it hangs for some reason)
		{"file:///etc/passwd", http.StatusBadRequest},         // file protocol not allowed
	}

	for _, tt := range tests {
		req, err := http.NewRequest(http.MethodGet, "/git?url="+tt.url, nil)
		if err != nil {
			t.Fatal(err)
		}
		rr := httptest.NewRecorder()
		gitHandler(rr, req)

		if status := rr.Code; status != tt.expectedCode && tt.expectedCode != http.StatusOK {
			// Note: OK might become InternalServerError if fetch fails, but checking for BadRequest specifically.
			t.Errorf("handler returned wrong status code for url %s: got %v want %v",
				tt.url, status, tt.expectedCode)
		}
	}
}

func resetSaveTimer() {
	lastFetchMu.Lock()
	defer lastFetchMu.Unlock()
	if saveTimer != nil {
		saveTimer.Stop()
		saveTimer = nil
	}
}

// Override global variables for test
// Note: In a real app we might want to dependency inject these,
// but for this simple script we modify package globals.
func setupTest(t *testing.T) {
	t.Helper()

	resetSaveTimer()

	tmpDir := t.TempDir()
	gitStorePath = tmpDir
	persistencePath = tmpDir + "/last-fetch.json" // Use simple path join for test
	fetchTimeout = time.Minute

	// Reset lastFetch map
	lastFetchMu.Lock()
	lastFetch = make(map[string]time.Time)
	lastFetchMu.Unlock()

	// Initialize semaphore for tests
	semaphore = make(chan struct{}, 100)

	// Initialize caches for tests
	repoCacheMaxCostBytes = 1024 * 1024 // 1MB for test
	invalidRepoCacheMaxEntries = 100
	InitRepoCache()
	InitInvalidRepoCache()

	t.Cleanup(func() {
		resetSaveTimer()
		CloseRepoCache()
		CloseInvalidRepoCache()
	})
}

func TestGitHandler_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	setupTest(t)

	tests := []struct {
		name         string
		url          string
		expectedCode int
	}{
		{
			name:         "Valid public repo",
			url:          "https://github.com/google/oss-fuzz-vulns.git", // Small repo
			expectedCode: http.StatusOK,
		},
		{
			name:         "Non-existent repo",
			url:          "https://github.com/google/this-repo-does-not-exist-12345.git",
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/git?url="+tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			gitHandler(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedCode)
			}
		})
	}
}

func TestCacheHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	setupTest(t)

	tests := []struct {
		name         string
		url          string
		expectedCode int
	}{
		{
			name:         "Valid public repo",
			url:          "https://github.com/google/oss-fuzz-vulns.git", // Small repo
			expectedCode: http.StatusOK,
		},
		{
			name:         "Non-existent repo",
			url:          "https://github.com/google/this-repo-does-not-exist-12345.git",
			expectedCode: http.StatusForbidden,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqProto := &pb.CacheRequest{Url: tt.url}
			body, _ := proto.Marshal(reqProto)
			req, err := http.NewRequest(http.MethodPost, "/cache", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			cacheHandler(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedCode)
			}
		})
	}
}

func TestAffectedCommitsHandler(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	setupTest(t)

	tests := []struct {
		name         string
		url          string
		introduced   []string
		fixed        []string
		lastAffected []string
		limit        []string
		invalidType  []string
		expectedCode int
		expectedBody []string
	}{
		{
			name:         "Valid range in public repo",
			url:          "https://github.com/google/oss-fuzz-vulns.git",
			introduced:   []string{"3350c55f9525cb83fc3e0b61bde076433c2da8dc"},
			fixed:        []string{"8920ed8e47c660a0c20c28cb1004a600780c5b59"},
			expectedCode: http.StatusOK,
			expectedBody: []string{"3350c55f9525cb83fc3e0b61bde076433c2da8dc"},
		},
		{
			name:         "Invalid mixed limit and fixed",
			url:          "https://github.com/google/oss-fuzz-vulns.git",
			introduced:   []string{"3350c55f9525cb83fc3e0b61bde076433c2da8dc"},
			fixed:        []string{"8920ed8e47c660a0c20c28cb1004a600780c5b59"},
			limit:        []string{"996962b987c856bf751948e55b9366751e806c64"},
			expectedCode: http.StatusBadRequest,
		},
		{
			name:         "Non-existent repo",
			url:          "https://github.com/google/this-repo-does-not-exist-12345.git",
			introduced:   []string{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
			expectedCode: http.StatusForbidden,
		},
		{
			name:         "Invalid event type",
			url:          "https://github.com/google/oss-fuzz-vulns.git",
			invalidType:  []string{"3350c55f9525cb83fc3e0b61bde076433c2da8dc"},
			expectedCode: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var events []*pb.Event
			for _, h := range tt.introduced {
				events = append(events, &pb.Event{EventType: pb.EventType_INTRODUCED, Hash: h})
			}
			for _, h := range tt.fixed {
				events = append(events, &pb.Event{EventType: pb.EventType_FIXED, Hash: h})
			}
			for _, h := range tt.lastAffected {
				events = append(events, &pb.Event{EventType: pb.EventType_LAST_AFFECTED, Hash: h})
			}
			for _, h := range tt.limit {
				events = append(events, &pb.Event{EventType: pb.EventType_LIMIT, Hash: h})
			}
			for _, h := range tt.invalidType {
				events = append(events, &pb.Event{EventType: 999, Hash: h})
			}

			reqProto := &pb.AffectedCommitsRequest{
				Url:    tt.url,
				Events: events,
			}

			body, _ := proto.Marshal(reqProto)
			req, err := http.NewRequest(http.MethodPost, "/affected-commits", bytes.NewBuffer(body))
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			affectedCommitsHandler(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedCode)
			}

			if tt.expectedBody == nil {
				return
			}

			respBody := &pb.AffectedCommitsResponse{}
			if err := proto.Unmarshal(rr.Body.Bytes(), respBody); err != nil {
				t.Fatalf("Failed to unmarshal proto response: %v", err)
			}

			var gotHashes []string
			for _, c := range respBody.GetCommits() {
				gotHashes = append(gotHashes, hex.EncodeToString(c.GetHash()))
			}
			if gotHashes == nil {
				gotHashes = []string{}
			}

			if diff := cmp.Diff(tt.expectedBody, gotHashes); diff != "" {
				t.Errorf("handler returned wrong body (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTagsHandler(t *testing.T) {
	setupTest(t)

	tests := []struct {
		name         string
		url          string
		expectedCode int
		expectedTags map[string]string
	}{
		{
			name:         "Valid repo with tags",
			url:          "https://github.com/oliverchang/osv-test.git",
			expectedCode: http.StatusOK,
			expectedTags: map[string]string{
				"v0.2":                        "8d8242f545e9cec3e6d0d2e3f5bde8be1c659735",
				"branch-v0.1.1":               "4c155795426727ea05575bd5904321def23c03f4",
				"branch-v0.1.1-with-fix":      "b9b3fd4732695b83c3068b7b6a14bb372ec31f98",
				"branch_1_cherrypick_regress": "febfac1940086bc1f6d3dc33fda0a1d1ba336209",
				"v0.1":                        "a2ba949290915d445d34d0e8e9de2e7ce38198fc",
				"v0.1.1":                      "b1c95a196f22d06fcf80df8c6691cd113d8fefff",
			},
		},
		{
			name: "Repo exist but no tags",
			// This repo hasn't gotten a commit in 8 years so should be fairly stable for our testing.
			url:          "https://github.com/torvalds/test-tlb.git",
			expectedCode: http.StatusNoContent,
			expectedTags: nil,
		},
		{
			name:         "Non-existent repo",
			url:          "https://github.com/google/this-repo-does-not-exist-12345.git",
			expectedCode: http.StatusNotFound,
			expectedTags: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "/tags?url="+tt.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			rr := httptest.NewRecorder()
			tagsHandler(rr, req)

			if status := rr.Code; status != tt.expectedCode {
				t.Errorf("handler returned wrong status code: got %v want %v",
					status, tt.expectedCode)
			}

			if tt.expectedTags != nil {
				respBody := &pb.TagsResponse{}
				if err := proto.Unmarshal(rr.Body.Bytes(), respBody); err != nil {
					t.Fatalf("Failed to unmarshal proto response: %v", err)
				}

				gotTags := make(map[string]string)
				for _, ref := range respBody.GetTags() {
					gotTags[ref.GetLabel()] = hex.EncodeToString(ref.GetHash())
				}

				if diff := cmp.Diff(tt.expectedTags, gotTags); diff != "" {
					t.Errorf("handler returned wrong tags (-want +got):\n%s", diff)
				}
			}
		})
	}
}
