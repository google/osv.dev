package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestAssignIDs(t *testing.T) {
	tests := []struct {
		name         string
		prefix       string
		format       fileFormat
		templateName string
		existingName string
		expectedID   string
	}{
		{
			name:         "OSV YAML",
			prefix:       "OSV",
			format:       fileFormatYAML,
			templateName: "OSV-0000-abc.yaml",
			existingName: "OSV-2026-10.yaml",
			expectedID:   "OSV-2026-11",
		},
		{
			name:         "TEST JSON",
			prefix:       "TEST",
			format:       fileFormatJSON,
			templateName: "TEST-0000-def.json",
			existingName: "TEST-2026-20.json",
			expectedID:   "TEST-2026-21",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// 1. Copy existing assigned vulnerability from testdata to set counter.
			existingPath := filepath.Join("testdata", tt.existingName)
			existingData, err := os.ReadFile(existingPath)
			if err != nil {
				t.Fatalf("failed to read existing ID: %v", err)
			}
			err = os.WriteFile(filepath.Join(tmpDir, tt.existingName), existingData, 0600)
			if err != nil {
				t.Fatalf("failed to copy existing ID: %v", err)
			}

			// 2. Setup unassigned vulnerability using template.
			templatePath := filepath.Join("testdata", tt.templateName)
			templateData, err := os.ReadFile(templatePath)
			if err != nil {
				t.Fatalf("failed to read template %s: %v", templatePath, err)
			}
			destPath := filepath.Join(tmpDir, tt.templateName)
			if err := os.WriteFile(destPath, templateData, 0600); err != nil {
				t.Fatalf("failed to setup unassigned vuln: %v", err)
			}

			// 3. Run assignIDs.
			if err := assignIDs(tt.prefix, tmpDir, tt.format); err != nil {
				t.Fatalf("assignIDs failed: %v", err)
			}

			// 4. Verify results.
			ext := formatToExtension[tt.format]
			expectedFilename := tt.expectedID + ext
			gotPath := filepath.Join(tmpDir, expectedFilename)
			if _, err := os.Stat(gotPath); os.IsNotExist(err) {
				t.Errorf("Expected %s to exist", gotPath)
				return
			}

			if _, err := os.Stat(destPath); !os.IsNotExist(err) {
				t.Errorf("Expected old file %s to be removed", tt.templateName)
			}

			gotData, err := os.ReadFile(gotPath)
			if err != nil {
				t.Fatalf("failed to read assigned vuln %s: %v", gotPath, err)
			}

			wantData, err := os.ReadFile(filepath.Join("testdata", expectedFilename))
			if err != nil {
				t.Fatalf("failed to read expected vuln: %v", err)
			}

			// Trim space to be robust against minor formatting differences,
			// for example trailing newlines.
			if !bytes.Equal(bytes.TrimSpace(gotData), bytes.TrimSpace(wantData)) {
				t.Errorf("Data fidelity mismatch for %s:\nGot:\n%s\nWant:\n%s", tt.expectedID, string(gotData), string(wantData))
			}

			// Verify .id-allocator was created.
			if _, err := os.Stat(filepath.Join(tmpDir, ".id-allocator")); os.IsNotExist(err) {
				t.Errorf("Expected .id-allocator to exist")
			}
		})
	}
}
