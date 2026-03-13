package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

// Override global variables for test
// Note: In a real app we might want to dependency inject these,
// but for this simple script we modify package globals.
func setupTest(t *testing.T) {
	t.Helper()
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

	// Stop any existing timer
	if saveTimer != nil {
		saveTimer.Stop()
		saveTimer = nil
	}
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
			body, _ := json.Marshal(map[string]string{"url": tt.url})
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
