package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestNormalizeRepo(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "HTTPS URL with .git",
			input:    "https://github.com/google/osv.dev.git",
			expected: "github.com/google/osv.dev",
		},
		{
			name:     "HTTPS URL without .git",
			input:    "https://github.com/google/osv.dev",
			expected: "github.com/google/osv.dev",
		},
		{
			name:     "URL with trailing slash",
			input:    "https://github.com/google/osv.dev/",
			expected: "github.com/google/osv.dev",
		},
		{
			name:     "No scheme URL",
			input:    "github.com/google/osv.dev",
			expected: "github.com/google/osv.dev",
		},
		{
			name:     "No scheme with .git",
			input:    "github.com/google/osv-scanner.git",
			expected: "github.com/google/osv-scanner",
		},
		{
			name:     "Whitespace in URL",
			input:    "  https://github.com/google/osv.dev.git  ",
			expected: "github.com/google/osv.dev",
		},
		{
			name:     "SSH URL format git@",
			input:    "git@github.com:google/osv.dev.git",
			expected: "",
		},
		{
			name:     "SSH URL format ssh://",
			input:    "ssh://git@github.com/google/osv.dev.git",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeRepo(tt.input)
			if got != tt.expected {
				t.Errorf("normalizeRepo(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

func TestParseYAMLEntries(t *testing.T) {
	yamlContent := []byte(`
- type: URL
  value: "  https://github.com/google/osv.dev.git  "
  consider_all_branches: true
  cherrypicks_introduced: true
- type: REGEX
  value: 'github\.com/google/osv-.*'
  cherrypicks: true
- type: url
  value: "https://github.com/noflags/repo.git"
- type: regex
  value: '[invalid regex'
- type: unknown
  value: "https://github.com/google/osv.dev"
- type: url
  value: "git@github.com:ssh/isnot.supported.git"
`)

	want := []RepoAllowListEntity{
		// Normalized URL
		{
			Type:                  "url",
			Value:                 "github.com/google/osv.dev",
			ConsiderAllBranches:   true,
			CherrypicksIntroduced: true,
			CherrypicksFixed:      false,
			CherrypicksLimit:      false,
		},
		// Regex type and cherrypicks: true populates all 3 event types
		{
			Type:                  "regex",
			Value:                 `github\.com/google/osv-.*`,
			ConsiderAllBranches:   false,
			CherrypicksIntroduced: true,
			CherrypicksFixed:      true,
			CherrypicksLimit:      true,
		},
		// No flags set (Shouldn't really happen)
		{
			Type:                  "url",
			Value:                 "github.com/noflags/repo",
			ConsiderAllBranches:   false,
			CherrypicksIntroduced: false,
			CherrypicksFixed:      false,
			CherrypicksLimit:      false,
		},
	}

	got, err := parseYAMLEntries(yamlContent)
	if err != nil {
		t.Fatalf("parseYAMLEntries returned unexpected error: %v", err)
	}

	if len(got) != len(want) {
		t.Fatalf("expected %d valid entries, got %d: %+v", len(want), len(got), got)
	}

	for i, wantEntry := range want {
		if got[i] != wantEntry {
			t.Errorf("entry %d mismatch:\n got: %+v\nwant: %+v", i, got[i], wantEntry)
		}
	}
}

func TestRun_InvalidFile(t *testing.T) {
	err := run(context.Background(), "non_existent_file.yaml", "test-project", true, false)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}

	tmpDir := t.TempDir()
	badYAMLPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(badYAMLPath, []byte("invalid: yaml: ["), 0644); err != nil {
		t.Fatalf("failed creating bad yaml file: %v", err)
	}

	err = run(context.Background(), badYAMLPath, "test-project", true, false)
	if err == nil {
		t.Error("expected error for invalid YAML file, got nil")
	}
}
