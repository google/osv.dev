package main

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSanitizeEcosystem(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Go", "Go"},
		{"Rocky Linux", "Rocky_Linux"},
		{"crates.io", "crates__io"},
		{"  spaced  ", "spaced"},
	}

	for _, test := range tests {
		got := sanitizeEcosystem(test.input)
		if got != test.expected {
			t.Errorf("sanitizeEcosystem(%q) = %q, want %q", test.input, got, test.expected)
		}
	}
}

func TestChunkEntries(t *testing.T) {
	entries := make([]Entry, 105)
	for i := range 105 {
		entries[i] = Entry{ID: "id"}
	}

	chunks := chunkEntries(entries, 50)
	if len(chunks) != 3 {
		t.Errorf("expected 3 chunks, got %d", len(chunks))
	}
	if len(chunks[0]) != 50 {
		t.Errorf("expected chunk 0 to have 50 entries, got %d", len(chunks[0]))
	}
	if len(chunks[1]) != 50 {
		t.Errorf("expected chunk 1 to have 50 entries, got %d", len(chunks[1]))
	}
	if len(chunks[2]) != 5 {
		t.Errorf("expected chunk 2 to have 5 entries, got %d", len(chunks[2]))
	}
}

func TestGenerateSitemaps(t *testing.T) {
	tmpDir := t.TempDir()

	entries := map[string][]Entry{
		"Go": {
			{ID: "GO-1", LastModified: time.Unix(1000, 0).UTC()},
			{ID: "GO-2", LastModified: time.Unix(2000, 0).UTC()},
		},
		"Rocky Linux": {
			{ID: "RL-1", LastModified: time.Unix(3000, 0).UTC()},
		},
		"LargeEco": make([]Entry, 60000), // Should split into 2 files (limit is 49999)
	}

	// Fill LargeEco
	for i := range 60000 {
		entries["LargeEco"][i] = Entry{
			ID:           fmt.Sprintf("LE-%d", i),
			LastModified: time.Unix(int64(i), 0).UTC(),
		}
	}

	err := generateSitemaps(context.Background(), nil, tmpDir, "https://example.com", entries)
	if err != nil {
		t.Fatalf("generateSitemaps failed: %v", err)
	}

	// Check files
	files, _ := filepath.Glob(filepath.Join(tmpDir, "*.xml"))
	expectedFiles := []string{
		"sitemap_Go.xml",
		"sitemap_Rocky_Linux.xml",
		"sitemap_LargeEco_1.xml",
		"sitemap_LargeEco_2.xml",
		"sitemap_index.xml",
	}

	fileMap := make(map[string]bool)
	for _, f := range files {
		fileMap[filepath.Base(f)] = true
	}

	for _, f := range expectedFiles {
		if !fileMap[f] {
			t.Errorf("expected file %s not found", f)
		}
	}

	// Verify content of sitemap_Go.xml
	content, err := os.ReadFile(filepath.Join(tmpDir, "sitemap_Go.xml"))
	if err != nil {
		t.Fatalf("error reading sitemap_Go.xml: %v", err)
	}
	var urlSet URLSet
	if err := xml.Unmarshal(content, &urlSet); err != nil {
		t.Fatalf("error unmarshalling sitemap_Go.xml: %v", err)
	}
	if len(urlSet.URLs) != 2 {
		t.Errorf("expected 2 URLs in sitemap_Go.xml, got %d", len(urlSet.URLs))
	}
	// Verify sorting (ascending)
	if urlSet.URLs[0].Loc != "https://example.com/vulnerability/GO-1" {
		t.Errorf("expected GO-1 first (older), got %s", urlSet.URLs[0].Loc)
	}

	// Verify content of sitemap_index.xml
	content, err = os.ReadFile(filepath.Join(tmpDir, "sitemap_index.xml"))
	if err != nil {
		t.Fatalf("error reading sitemap_index.xml: %v", err)
	}
	var index SitemapIndex
	if err := xml.Unmarshal(content, &index); err != nil {
		t.Fatalf("error unmarshalling sitemap_index.xml: %v", err)
	}

	// We expect 4 entries in index: Go, Rocky Linux, LargeEco_1, LargeEco_2
	if len(index.Sitemaps) != 4 {
		t.Errorf("expected 4 sitemaps in index, got %d", len(index.Sitemaps))
	}

	// Check LargeEco entries in index
	foundLE1 := false
	foundLE2 := false
	for _, s := range index.Sitemaps {
		if strings.HasSuffix(s.Loc, "sitemap_LargeEco_1.xml") {
			foundLE1 = true
		}
		if strings.HasSuffix(s.Loc, "sitemap_LargeEco_2.xml") {
			foundLE2 = true
		}
	}
	if !foundLE1 || !foundLE2 {
		t.Errorf("missing LargeEco sitemaps in index")
	}
}
