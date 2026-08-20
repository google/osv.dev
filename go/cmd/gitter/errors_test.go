package main

import (
	"errors"
	"testing"
)

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

func TestExtractHTTPStatusCode(t *testing.T) {
	tests := []struct {
		err      error
		expected int
	}{
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 429"), 429},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 403"), 403},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 404"), 404},
		{errors.New("error: RPC failed; HTTP 500 curl 22 The requested URL returned error: 500"), 500},
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 502"), 502},
		{errors.New("fatal: repository not found"), 0},
		{nil, 0},
	}

	for _, tt := range tests {
		if result := extractHTTPStatusCode(tt.err); result != tt.expected {
			t.Errorf("extractHTTPStatusCode(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRateLimitError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 429"), true},
		{errors.New("fatal: remote error: GitLab is currently unable to handle this request due to load (ID a2b5c730282383b9-ORD)."), true}, //nolint:revive // Testing exact error message from remote git host
		{errors.New("fatal: You have exceeded a secondary rate limit"), true},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRateLimitError(tt.err); result != tt.expected {
			t.Errorf("isRateLimitError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRemoteHostError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: unable to access 'https://git.example.com/repo': The requested URL returned error: 500"), true},
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 502"), true},
		{errors.New("fatal: unable to access 'https://git.example.com/repo/': Could not connect to server"), true},
		{errors.New("fatal: unable to access 'https://git.example.com/repo/': Connection reset by peer"), true},
		{errors.New("fatal: early EOF\nfatal: fetch-pack: invalid index-pack output"), true},
		{errors.New("fatal: unable to access 'https://github.com/repo': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRemoteHostError(tt.err); result != tt.expected {
			t.Errorf("isRemoteHostError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsAuthError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: could not read Username for 'https://github.com': terminal prompts disabled"), true},
		{errors.New("fatal: Authentication failed for 'https://github.com/example/repo.git/'"), true},
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isAuthError(tt.err); result != tt.expected {
			t.Errorf("isAuthError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsForbiddenError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 403"), true},
		{errors.New("remote: 403 Forbidden"), true},
		{errors.New("fatal: unable to access 'https://gitlab.example.com/repo': The requested URL returned error: 429"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isForbiddenError(tt.err); result != tt.expected {
			t.Errorf("isForbiddenError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("remote: Repository not found"), true},
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 404"), true},
		{errors.New("fatal: unable to access 'https://github.com/example/repo/': The requested URL returned error: 403"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isNotFoundError(tt.err); result != tt.expected {
			t.Errorf("isNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsRefNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("ref cannot be empty"), true},
		{errors.New("failed to resolve target ref 'non-existent-branch'"), true},
		{errors.New("git cat-file failed: fatal: not found or invalid"), true},
		{errors.New("fatal: Authentication failed"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isRefNotFoundError(tt.err); result != tt.expected {
			t.Errorf("isRefNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}

func TestIsFileNotFoundError(t *testing.T) {
	tests := []struct {
		err      error
		expected bool
	}{
		{errors.New("git cat-file failed: fatal: Not a valid object name 1234abcd"), true},
		{errors.New("file does not exist in commit"), true},
		{errors.New("fatal: Authentication failed"), false},
		{nil, false},
	}

	for _, tt := range tests {
		if result := isFileNotFoundError(tt.err); result != tt.expected {
			t.Errorf("isFileNotFoundError(%v) = %v, expected %v", tt.err, result, tt.expected)
		}
	}
}
