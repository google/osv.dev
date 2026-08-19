// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

const sampleFilelistYAML = `
0ad:
  0.0.17-1:
  - main/0/0ad/0ad_0.0.17-1_copyright
  - main/0/0ad/0ad_0.0.17-1_changelog
  testing:
  - main/0/0ad/testing_copyright
  - main/0/0ad/testing_changelog
  unstable:
  - main/0/0ad/unstable_changelog
  - main/0/0ad/unstable_copyright
  - main/0/0ad/unstable_NEWS
0ad-data:
  unstable:
  - main/0/0ad-data/unstable_changelog
  - main/0/0ad-data/unstable_copyright
non-free-pkg:
  unstable:
  - non-free/n/non-free-pkg/unstable_changelog
  - non-free/n/non-free-pkg/unstable_copyright
no-unstable-pkg:
  stable:
  - main/n/no-unstable-pkg/stable_copyright
no-copyright-pkg:
  unstable:
  - main/n/no-copyright-pkg/unstable_changelog
'0xffff':
  0.6.1-1:
  - main/0/0xffff/0xffff_0.6.1-1_changelog
  unstable:
  - "main/0/0xffff/unstable_changelog"
  - 'main/0/0xffff/unstable_copyright'
`

func TestExtractUnstableCopyright(t *testing.T) {
	tests := []struct {
		name         string
		yamlContent  string
		prefixFilter string
		expected     []string
	}{
		{
			name:         "Sample filelist with main/ filter",
			yamlContent:  sampleFilelistYAML,
			prefixFilter: "main/",
			expected: []string{
				"main/0/0ad/unstable_copyright",
				"main/0/0ad-data/unstable_copyright",
				"main/0/0xffff/unstable_copyright",
			},
		},
		{
			name:         "Sample filelist without filter",
			yamlContent:  sampleFilelistYAML,
			prefixFilter: "",
			expected: []string{
				"main/0/0ad/unstable_copyright",
				"main/0/0ad-data/unstable_copyright",
				"non-free/n/non-free-pkg/unstable_copyright",
				"main/0/0xffff/unstable_copyright",
			},
		},
		{
			name:         "Empty YAML",
			yamlContent:  "",
			prefixFilter: "main/",
			expected:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := strings.NewReader(tt.yamlContent)
			got, err := ExtractUnstableCopyright(r, tt.prefixFilter)
			if err != nil {
				t.Fatalf("ExtractUnstableCopyright unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.expected) {
				t.Errorf("ExtractUnstableCopyright() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestGenerateCurlConfiguration(t *testing.T) {
	tempDir := t.TempDir()
	configPath := filepath.Join(tempDir, "curl_config")

	files := []string{
		"main/0/0ad/unstable_copyright",
		"main/0/0xffff/unstable_copyright",
	}
	urlBase := "https://metadata.ftp-master.debian.org/changelogs"

	if err := GenerateCurlConfiguration(files, urlBase, configPath); err != nil {
		t.Fatalf("GenerateCurlConfiguration returned error: %v", err)
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("Failed to read generated config: %v", err)
	}

	expected := "--output main/0/0ad/unstable_copyright\n" +
		"url = https://metadata.ftp-master.debian.org/changelogs/main/0/0ad/unstable_copyright\n" +
		"--output main/0/0xffff/unstable_copyright\n" +
		"url = https://metadata.ftp-master.debian.org/changelogs/main/0/0xffff/unstable_copyright\n"

	if string(content) != expected {
		t.Errorf("GenerateCurlConfiguration() =\n%s\nwant:\n%s", string(content), expected)
	}
}

func TestDownloadFilesConcurrently(t *testing.T) {
	fileMap := map[string]string{
		"main/a/pkg1/unstable_copyright": "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nSource: https://github.com/foo/pkg1\n",
		"main/b/pkg2/unstable_copyright": "Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\nSource: https://github.com/bar/pkg2\n",
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if content, ok := fileMap[path]; ok {
			w.WriteHeader(http.StatusOK)
			_, _ = fmt.Fprint(w, content)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer ts.Close()

	tempDir := t.TempDir()
	ctx := context.Background()
	client := ts.Client()

	filelist := []string{
		"main/a/pkg1/unstable_copyright",
		"main/b/pkg2/unstable_copyright",
	}

	if err := DownloadFilesConcurrently(ctx, client, filelist, ts.URL, tempDir, 2, false, 0.05); err != nil {
		t.Fatalf("DownloadFilesConcurrently failed: %v", err)
	}

	for _, relPath := range filelist {
		fullPath := filepath.Join(tempDir, relPath)
		data, err := os.ReadFile(fullPath)
		if err != nil {
			t.Errorf("Failed to read %s: %v", relPath, err)
			continue
		}
		if string(data) != fileMap[relPath] {
			t.Errorf("Content mismatch for %s: got %q, want %q", relPath, string(data), fileMap[relPath])
		}
	}

	// Test failure threshold breach
	badFileList := []string{
		"main/missing/1",
		"main/missing/2",
	}
	err := DownloadFilesConcurrently(ctx, client, badFileList, ts.URL, tempDir, 2, false, 0.05)
	if err == nil {
		t.Errorf("Expected failure threshold error, got nil")
	}
}
