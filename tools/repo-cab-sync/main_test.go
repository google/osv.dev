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
- type: REGEX
  value: 'github\.com/google/osv-.*'
- type: regex
  value: '[invalid regex'
- type: unknown
  value: "https://github.com/google/osv.dev"
- type: url
  value: "git@github.com:google/osv.dev.git"
`)

	entries, err := parseYAMLEntries(yamlContent)
	if err != nil {
		t.Fatalf("parseYAMLEntries returned unexpected error: %v", err)
	}

	// Should normalize types, trim values, and skip invalid regex, unrecognized types, and SSH URLs
	if len(entries) != 2 {
		t.Fatalf("expected 2 valid entries, got %d: %+v", len(entries), entries)
	}

	// First entry should be normalized URL
	if entries[0].Type != "url" || entries[0].Value != "github.com/google/osv.dev" {
		t.Errorf("entry 0 mismatch: got type=%q val=%q, want type=url val=github.com/google/osv.dev", entries[0].Type, entries[0].Value)
	}

	// Second entry should preserve regex string
	if entries[1].Type != "regex" || entries[1].Value != `github\.com/google/osv-.*` {
		t.Errorf("entry 1 mismatch: got type=%q val=%q, want type=regex val=github\\.com/google/osv-.*", entries[1].Type, entries[1].Value)
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
