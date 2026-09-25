package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv.dev/go/internal/models"
)

func TestDevStore_GetVulnerability(t *testing.T) {
	t.Parallel()

	dataDir := filepath.Join(".", "testdata")
	store, err := NewDevStore(dataDir, filepath.Join("..", "..", "source.yaml"))
	if err != nil {
		t.Fatalf("failed to initialize DevStore: %v", err)
	}

	ctx := context.Background()

	t.Run("Get existing vulnerability with metadata", func(t *testing.T) {
		t.Parallel()
		vuln, ref, err := store.GetWithMetadata(ctx, "CVE-2021-44228")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if vuln.GetId() != "CVE-2021-44228" {
			t.Errorf("expected ID CVE-2021-44228, got %s", vuln.GetId())
		}
		if ref.Source != "cve-osv" {
			t.Errorf("expected source cve-osv, got %s", ref.Source)
		}
		if ref.Path != "2021/CVE-2021-44228.json" {
			t.Errorf("expected path 2021/CVE-2021-44228.json, got %s", ref.Path)
		}
	})

	t.Run("Get non-existent vulnerability returns ErrNotFound", func(t *testing.T) {
		t.Parallel()
		_, _, err := store.GetWithMetadata(ctx, "NON-EXISTENT-9999")
		if !errors.Is(err, models.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})

	t.Run("Exists check", func(t *testing.T) {
		t.Parallel()
		exists, err := store.Exists(ctx, "CVE-2021-44228")
		if err != nil || !exists {
			t.Errorf("expected exists=true, got %v, err=%v", exists, err)
		}

		exists, err = store.Exists(ctx, "UNKNOWN-BUG")
		if err != nil || exists {
			t.Errorf("expected exists=false, got %v, err=%v", exists, err)
		}
	})
}

func TestDevStore_SourceRepository(t *testing.T) {
	t.Parallel()

	dataDir := filepath.Join(".", "testdata")
	sourcesFile := filepath.Join(dataDir, "sources.yaml")
	store, err := NewDevStore(dataDir, sourcesFile)
	if err != nil {
		t.Fatalf("failed to initialize DevStore: %v", err)
	}

	ctx := context.Background()

	t.Run("Get loaded source repository", func(t *testing.T) {
		t.Parallel()
		repo, err := store.Get(ctx, "ubuntu-cve")
		if err != nil {
			t.Fatalf("unexpected error getting ubuntu-cve repo: %v", err)
		}
		if repo.Name != "ubuntu-cve" {
			t.Errorf("expected repo name ubuntu-cve, got %s", repo.Name)
		}
		if repo.Link == "" {
			t.Errorf("expected non-empty Link for ubuntu-cve repo")
		}
	})

	t.Run("Get non-existent source repository returns ErrNotFound", func(t *testing.T) {
		t.Parallel()
		_, err := store.Get(ctx, "non-existent-repo")
		if !errors.Is(err, models.ErrNotFound) {
			t.Errorf("expected ErrNotFound, got %v", err)
		}
	})
}

func TestDevStore_Relations(t *testing.T) {
	t.Parallel()

	dataDir := filepath.Join(".", "testdata")
	store, err := NewDevStore(dataDir, "")
	if err != nil {
		t.Fatalf("failed to initialize DevStore: %v", err)
	}

	ctx := context.Background()

	t.Run("GetAliases across records", func(t *testing.T) {
		t.Parallel()
		res, err := store.GetAliases(ctx, "ALIAS-CVE-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Contains(res.Aliases, "CVE-1") || !slices.Contains(res.Aliases, "ALIAS") {
			t.Errorf("expected aliases to contain CVE-1 and ALIAS, got %v", res.Aliases)
		}
	})

	t.Run("GetUpstreamHierarchy", func(t *testing.T) {
		t.Parallel()
		hier, err := store.GetUpstreamHierarchy(ctx, "USN-6315-1")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hier.Roots) == 0 {
			t.Errorf("expected non-empty roots in hierarchy")
		}
		if !slices.Contains(hier.Roots, "CVE-2023-21400") {
			t.Errorf("expected CVE-2023-21400 in upstream roots, got %v", hier.Roots)
		}
		if len(hier.Graph["CVE-2023-21400"]) == 0 {
			t.Errorf("expected CVE-2023-21400 edges in graph")
		}
	})

	t.Run("GetDownstreamHierarchy", func(t *testing.T) {
		t.Parallel()
		hier, err := store.GetDownstreamHierarchy(ctx, "CVE-2023-21400")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(hier.Roots) == 0 {
			t.Errorf("expected non-empty roots in hierarchy")
		}
		if !slices.Contains(hier.Roots, "UBUNTU-CVE-2023-21400") {
			t.Errorf("expected UBUNTU-CVE-2023-21400 in downstream roots, got %v", hier.Roots)
		}
	})

	t.Run("GetUpstreamHierarchy handles cycles without infinite loop", func(t *testing.T) {
		t.Parallel()
		_, err := store.GetUpstreamHierarchy(ctx, "CYCLE-ROOT-1")
		if err == nil {
			t.Errorf("expected error on cyclic record, got nil")
		}
	})
}

func TestDevStore_Search(t *testing.T) {
	t.Parallel()

	dataDir := filepath.Join(".", "testdata")
	store, err := NewDevStore(dataDir, "")
	if err != nil {
		t.Fatalf("failed to initialize DevStore: %v", err)
	}

	ctx := context.Background()

	t.Run("Search all returns all items paginated with cursor", func(t *testing.T) {
		t.Parallel()
		page1, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			PageSize: 10,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(page1.Vulnerabilities) != 10 {
			t.Fatalf("expected 10 items on page 1, got %d", len(page1.Vulnerabilities))
		}
		if page1.NextAfterTime.IsZero() || page1.NextAfterID == "" {
			t.Fatalf("expected valid next cursor on page 1")
		}

		page2, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			PageSize:  10,
			AfterTime: page1.NextAfterTime,
			AfterID:   page1.NextAfterID,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(page2.Vulnerabilities) != 10 {
			t.Fatalf("expected 10 items on page 2, got %d", len(page2.Vulnerabilities))
		}
		// Ensure items on page 2 are distinct from page 1
		p1IDs := make(map[string]bool)
		for _, v := range page1.Vulnerabilities {
			p1IDs[v.ID] = true
		}
		for _, v := range page2.Vulnerabilities {
			if p1IDs[v.ID] {
				t.Errorf("duplicate item %s found across pages", v.ID)
			}
		}

		page3, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			PageSize:  10,
			AfterTime: page2.NextAfterTime,
			AfterID:   page2.NextAfterID,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(page3.Vulnerabilities) == 0 {
			t.Fatalf("expected non-empty page 3")
		}
	})

	t.Run("Search by query substring", func(t *testing.T) {
		t.Parallel()
		res, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			Query: "Log4Shell",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Vulnerabilities) == 0 || res.Vulnerabilities[0].ID != "CVE-2021-44228" {
			t.Errorf("expected to find Log4Shell CVE-2021-44228, got %v", res.Vulnerabilities)
		}
	})

	t.Run("Search by repository URL", func(t *testing.T) {
		t.Parallel()
		tmpDir := t.TempDir()
		gitVuln := `{
			"id": "GIT-VULN-1",
			"summary": "Git repo vuln",
			"affected": [
				{
					"ranges": [
						{
							"type": "GIT",
							"repo": "https://github.com/example/awesome-repo",
							"events": [{"introduced": "0"}]
						}
					]
				}
			]
		}`
		if err := os.WriteFile(filepath.Join(tmpDir, "GIT-VULN-1.json"), []byte(gitVuln), 0600); err != nil {
			t.Fatalf("failed to write test git vuln: %v", err)
		}
		gitStore, err := NewDevStore(tmpDir, "")
		if err != nil {
			t.Fatalf("failed to initialize DevStore: %v", err)
		}

		res, err := gitStore.Search(ctx, models.VulnerabilitySearchQuery{
			Query: "awesome-repo",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Vulnerabilities) == 0 || res.Vulnerabilities[0].ID != "GIT-VULN-1" {
			t.Fatalf("expected to find GIT-VULN-1 by repo URL query, got %v", res.Vulnerabilities)
		}
		if len(res.Vulnerabilities[0].Packages) == 0 || res.Vulnerabilities[0].Packages[0].Repo != "https://github.com/example/awesome-repo" {
			t.Errorf("expected package Repo to be populated, got %v", res.Vulnerabilities[0].Packages)
		}
	})

	t.Run("Search with legacy page parameter", func(t *testing.T) {
		t.Parallel()
		page1, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			PageSize: 10,
			Page:     1,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		page2, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			PageSize: 10,
			Page:     2,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(page1.Vulnerabilities) != 10 || len(page2.Vulnerabilities) != 10 {
			t.Fatalf("expected 10 items on page 1 and page 2, got %d and %d", len(page1.Vulnerabilities), len(page2.Vulnerabilities))
		}
		if page1.Vulnerabilities[0].ID == page2.Vulnerabilities[0].ID {
			t.Errorf("expected page 2 to have different items from page 1")
		}
	})

	t.Run("Search by ecosystem filter", func(t *testing.T) {
		t.Parallel()
		res, err := store.Search(ctx, models.VulnerabilitySearchQuery{
			Ecosystem: "PyPI",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(res.Vulnerabilities) == 0 {
			t.Errorf("expected PyPI vulnerabilities, got 0")
		}
		for _, v := range res.Vulnerabilities {
			matched := false
			for _, pkg := range v.Packages {
				if pkg.Package.GetEcosystem() == "PyPI" {
					matched = true
				}
			}
			if !matched {
				t.Errorf("expected all results to match PyPI ecosystem, found %s", v.ID)
			}
		}
	})

	t.Run("Autocomplete suggestions", func(t *testing.T) {
		t.Parallel()
		suggestions, err := store.Autocomplete(ctx, "CVE-2021", 5)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !slices.Contains(suggestions, "CVE-2021-44228") {
			t.Errorf("expected CVE-2021-44228 in suggestions, got %v", suggestions)
		}
	})

	t.Run("EcosystemCounts", func(t *testing.T) {
		t.Parallel()
		counts, err := store.EcosystemCounts(ctx)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(counts) == 0 {
			t.Errorf("expected non-empty ecosystem counts")
		}
		for _, c := range counts {
			if strings.Contains(c.Name, ":") {
				t.Errorf("expected ecosystem name without colon, got %s", c.Name)
			}
		}
	})
}

func TestDevStore_HotReload(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()

	record1 := `{"id": "HOT-1", "summary": "First version", "affected": []}`
	if err := os.WriteFile(filepath.Join(tmpDir, "HOT-1.json"), []byte(record1), 0600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	store, err := NewDevStore(tmpDir, "")
	if err != nil {
		t.Fatalf("failed to create DevStore: %v", err)
	}

	ctx := context.Background()

	vuln, _, err := store.GetWithMetadata(ctx, "HOT-1")
	if err != nil || vuln.GetSummary() != "First version" {
		t.Fatalf("expected First version, got %v, err=%v", vuln, err)
	}

	// Modify file on disk
	record1Updated := `{"id": "HOT-1", "summary": "Updated version", "affected": []}`
	if err := os.WriteFile(filepath.Join(tmpDir, "HOT-1.json"), []byte(record1Updated), 0600); err != nil {
		t.Fatalf("failed to update test file: %v", err)
	}

	// Immediately read again without recreating store
	vulnUpdated, _, err := store.GetWithMetadata(ctx, "HOT-1")
	if err != nil || vulnUpdated.GetSummary() != "Updated version" {
		t.Fatalf("expected hot reload to reflect 'Updated version', got %v, err=%v", vulnUpdated, err)
	}

	// Add brand new file
	record2 := `{"id": "HOT-2", "summary": "Second record", "affected": []}`
	if err := os.WriteFile(filepath.Join(tmpDir, "HOT-2.json"), []byte(record2), 0600); err != nil {
		t.Fatalf("failed to write second test file: %v", err)
	}

	vuln2, _, err := store.GetWithMetadata(ctx, "HOT-2")
	if err != nil || vuln2.GetSummary() != "Second record" {
		t.Fatalf("expected dynamically added file to be found, got %v, err=%v", vuln2, err)
	}
}
