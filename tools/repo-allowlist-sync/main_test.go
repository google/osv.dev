package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/osv.dev/go/osv/models"
)

func TestNormalizeRepo(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		expected    string
		expectError bool
	}{
		{
			name:        "Empty string",
			input:       "",
			expected:    "",
			expectError: true,
		},
		{
			name:        "HTTPS URL with .git",
			input:       "https://github.com/google/osv.dev.git",
			expected:    "github.com/google/osv.dev",
			expectError: false,
		},
		{
			name:        "HTTPS URL without .git",
			input:       "https://github.com/google/osv.dev",
			expected:    "github.com/google/osv.dev",
			expectError: false,
		},
		{
			name:        "URL with trailing slash",
			input:       "https://github.com/google/osv.dev/",
			expected:    "github.com/google/osv.dev",
			expectError: false,
		},
		{
			name:        "No scheme URL",
			input:       "github.com/google/osv.dev",
			expected:    "github.com/google/osv.dev",
			expectError: false,
		},
		{
			name:        "No scheme with .git",
			input:       "github.com/google/osv-scanner.git",
			expected:    "github.com/google/osv-scanner",
			expectError: false,
		},
		{
			name:        "Whitespace in URL",
			input:       "  https://github.com/google/osv.dev.git  ",
			expected:    "github.com/google/osv.dev",
			expectError: false,
		},
		{
			name:        "SSH URL format git@",
			input:       "git@github.com:google/osv.dev.git",
			expected:    "",
			expectError: true,
		},
		{
			name:        "SSH URL format ssh://",
			input:       "ssh://git@github.com/google/osv.dev.git",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeRepo(tt.input)
			if tt.expectError {
				if err == nil {
					t.Errorf("normalizeRepo(%q) expected error, got nil (result: %q)", tt.input, got)
				}
			} else {
				if err != nil {
					t.Errorf("normalizeRepo(%q) returned unexpected error: %v", tt.input, err)
				}
				if got != tt.expected {
					t.Errorf("normalizeRepo(%q) = %q, want %q", tt.input, got, tt.expected)
				}
			}
		})
	}
}

func TestParseYAMLEntries_Valid(t *testing.T) {
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
`)
	want := []models.RepoAllowList{
		{
			Type:                  "url",
			Value:                 "github.com/google/osv.dev",
			ConsiderAllBranches:   true,
			CherrypicksIntroduced: true,
			CherrypicksFixed:      false,
			CherrypicksLimit:      false,
		},
		{
			Type:                  "regex",
			Value:                 `github\.com/google/osv-.*`,
			ConsiderAllBranches:   false,
			CherrypicksIntroduced: true,
			CherrypicksFixed:      true,
			CherrypicksLimit:      true,
		},
		{
			Type:                  "url",
			Value:                 "github.com/noflags/repo",
			ConsiderAllBranches:   false,
			CherrypicksIntroduced: false,
			CherrypicksFixed:      false,
			CherrypicksLimit:      false,
		},
	}

	got, err := parseYAMLEntries(yamlContent, false)
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

func TestParseYAMLEntries_Invalid(t *testing.T) {
	invalidTests := []struct {
		name string
		yaml string
	}{
		{
			name: "Unknown YAML field",
			yaml: "- type: url\n  value: \"https://github.com/google/osv.dev\"\n  unknown_field: true\n",
		},
		{
			name: "Invalid regex",
			yaml: "- type: regex\n  value: '[invalid regex'\n",
		},
		{
			name: "Unrecognized entry type",
			yaml: "- type: unknown\n  value: \"https://github.com/google/osv.dev\"\n",
		},
		{
			name: "Unsupported SSH URL",
			yaml: "- type: url\n  value: \"git@github.com:ssh/isnot.supported.git\"\n",
		},
		{
			name: "Duplicate values",
			yaml: "- type: url\n  value: \"https://github.com/google/osv.dev.git\"\n- type: url\n  value: \"https://github.com/google/osv.dev\"\n",
		},
	}

	for _, tt := range invalidTests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := parseYAMLEntries([]byte(tt.yaml), false); err == nil {
				t.Errorf("parseYAMLEntries expected error for %s, got nil", tt.name)
			}
		})
	}
}

func TestRun_InvalidFile(t *testing.T) {
	err := run(context.Background(), "non_existent_file.yaml", "test-project", true, false, false)
	if err == nil {
		t.Error("expected error for non-existent file, got nil")
	}

	tmpDir := t.TempDir()
	badYAMLPath := filepath.Join(tmpDir, "bad.yaml")
	if err := os.WriteFile(badYAMLPath, []byte("invalid: yaml: ["), 0644); err != nil {
		t.Fatalf("failed creating bad yaml file: %v", err)
	}

	err = run(context.Background(), badYAMLPath, "test-project", true, false, false)
	if err == nil {
		t.Error("expected error for invalid YAML file, got nil")
	}
}

func TestRun_Validate(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("Valid YAML", func(t *testing.T) {
		validYAML := filepath.Join(tmpDir, "valid.yaml")
		if err := os.WriteFile(validYAML, []byte("- type: url\n  value: \"https://github.com/google/osv.dev\"\n- type: regex\n  value: 'github\\.com/google/.*'\n"), 0644); err != nil {
			t.Fatalf("failed creating valid yaml file: %v", err)
		}

		// Validate mode (validate=true) should succeed without needing a Datastore connection/project.
		if err := run(context.Background(), validYAML, "", true, true, true); err != nil {
			t.Errorf("run with validate=true returned unexpected error: %v", err)
		}
	})

	t.Run("Invalid YAML", func(t *testing.T) {
		invalidYAML := filepath.Join(tmpDir, "invalid.yaml")
		if err := os.WriteFile(invalidYAML, []byte("- type: unknown\n  value: \"https://github.com/google/osv.dev\"\n- type: regex\n  value: '[invalid regex'\n"), 0644); err != nil {
			t.Fatalf("failed creating invalid yaml file: %v", err)
		}

		err := run(context.Background(), invalidYAML, "", true, true, true)
		if err == nil {
			t.Error("expected error for invalid YAML file in validate mode, got nil")
		}
	})
}
