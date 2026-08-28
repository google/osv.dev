package website_test

import (
	"context"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/website"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type mockVulnStore struct {
	models.UnimplementedVulnerabilityStore
}

func (m mockVulnStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	return &osvschema.Vulnerability{Id: id}, nil
}

func (m mockVulnStore) GetWithMetadata(_ context.Context, id string) (*osvschema.Vulnerability, *models.VulnSourceRef, error) {
	if id == "UNKNOWN" || id == "UNKNOWN-1234" || id == "ALIAS-1234" {
		return nil, nil, models.ErrNotFound
	}

	return &osvschema.Vulnerability{Id: id}, &models.VulnSourceRef{ID: id, Source: "test", Path: id + ".json"}, nil
}

func (m mockVulnStore) Exists(_ context.Context, id string) (bool, error) {
	return id != "UNKNOWN" && id != "UNKNOWN-1234" && id != "ALIAS-1234", nil
}

type mockRelationsStore struct {
	models.UnimplementedRelationsStore
}

func (m mockRelationsStore) GetAliases(_ context.Context, id string) (*models.GetAliasResult, error) {
	if id == "ALIAS-1234" {
		return &models.GetAliasResult{
			Aliases: []string{"GHSA-1234"},
		}, nil
	}

	return nil, models.ErrNotFound
}

func (m mockRelationsStore) GetRelated(_ context.Context, _ string) (*models.GetRelatedResult, error) {
	return nil, models.ErrNotFound
}

func (m mockRelationsStore) GetUpstream(_ context.Context, _ string) (*models.GetUpstreamResult, error) {
	return nil, models.ErrNotFound
}

func (m mockRelationsStore) GetUpstreamHierarchy(_ context.Context, _ string) (*models.Hierarchy, error) {
	return nil, models.ErrNotFound
}

func (m mockRelationsStore) GetDownstreamHierarchy(_ context.Context, _ string) (*models.Hierarchy, error) {
	return nil, models.ErrNotFound
}

type mockSourceRepoStore struct{}

func (m mockSourceRepoStore) Get(_ context.Context, _ string) (*models.SourceRepository, error) {
	return &models.SourceRepository{
		Link: "https://example.com/source/",
	}, nil
}

func (m mockSourceRepoStore) Update(_ context.Context, _ string, _ *models.SourceRepository) error {
	return nil
}

func (m mockSourceRepoStore) All(_ context.Context) iter.Seq2[*models.SourceRepository, error] {
	return func(_ func(*models.SourceRepository, error) bool) {}
}

type mockVulnSearchStore struct {
	models.UnimplementedVulnerabilitySearchStore
}

func (m mockVulnSearchStore) Search(_ context.Context, _ models.VulnerabilitySearchQuery) (*models.VulnerabilitySearchResult, error) {
	return &models.VulnerabilitySearchResult{}, nil
}

func (m mockVulnSearchStore) Autocomplete(_ context.Context, _ string, _ int) ([]string, error) {
	return nil, nil
}

func (m mockVulnSearchStore) EcosystemCounts(_ context.Context) ([]models.EcosystemCount, error) {
	return nil, nil
}

type mockLinterStore struct {
	models.UnimplementedLinterStore
}

func (m mockLinterStore) ListSources(_ context.Context) ([]string, error) {
	return []string{"cve-osv", "ghsa"}, nil
}

func (m mockLinterStore) GetFindings(_ context.Context, source string) ([]byte, error) {
	if source == "ghsa" {
		return []byte(`{"findings":[]}`), nil
	}

	return nil, models.ErrNotFound
}

type mockTriageStore struct {
	models.UnimplementedTriageStore
}

func (m mockTriageStore) GetFile(_ context.Context, source, cveID string) ([]byte, error) {
	if source == "invalid-source" {
		return nil, models.ErrInvalidArgument
	}
	if cveID == "CVE-2024-1234" && (source == "test-nvd" || source == "cve") {
		return []byte(`{"id":"CVE-2024-1234"}`), nil
	}

	return nil, models.ErrNotFound
}

func newTestServer(t *testing.T, cfg website.Config) *website.Server {
	t.Helper()
	if cfg.StaticFS == nil {
		cfg.StaticFS = fstest.MapFS{
			"go/base.html":   &fstest.MapFile{Data: []byte(`<html>{{ block "content" . }}{{ end }}</html>`)},
			"go/404.html":    &fstest.MapFile{Data: []byte(`{{ define "content" }}404{{ end }}`)},
			"go/linter.html": &fstest.MapFile{Data: []byte(`{{ define "content" }}linter{{ end }}`)},
			"go/triage.html": &fstest.MapFile{Data: []byte(`{{ define "content" }}triage{{ end }}`)},
		}
	}
	if cfg.DocsFS == nil {
		cfg.DocsFS = fstest.MapFS{}
	}
	if cfg.Stores.Vuln == nil {
		cfg.Stores.Vuln = mockVulnStore{}
	}
	if cfg.Stores.Relations == nil {
		cfg.Stores.Relations = mockRelationsStore{}
	}
	if cfg.Stores.SourceRepo == nil {
		cfg.Stores.SourceRepo = mockSourceRepoStore{}
	}
	if cfg.Stores.VulnSearch == nil {
		cfg.Stores.VulnSearch = mockVulnSearchStore{}
	}
	if cfg.Stores.Linter == nil {
		cfg.Stores.Linter = mockLinterStore{}
	}
	if cfg.Stores.Triage == nil {
		cfg.Stores.Triage = mockTriageStore{}
	}
	if !cfg.Auth.BypassOAuth && cfg.Auth.ClientID == "" && cfg.Auth.ClientSecret == "" {
		cfg.Auth.BypassOAuth = true
	}
	srv, err := website.NewServer(cfg)
	if err != nil {
		t.Fatalf("failed creating test server: %v", err)
	}

	return srv
}

func TestNewServer_NilConfig(t *testing.T) {
	t.Parallel()

	validConfig := website.Config{
		StaticFS: fstest.MapFS{},
		DocsFS:   fstest.MapFS{},
		Stores: website.Stores{
			Vuln:       mockVulnStore{},
			Relations:  mockRelationsStore{},
			SourceRepo: mockSourceRepoStore{},
			VulnSearch: mockVulnSearchStore{},
			Linter:     mockLinterStore{},
			Triage:     mockTriageStore{},
		},
	}

	if _, err := website.NewServer(website.Config{}); err == nil {
		t.Errorf("expected error when config is empty, got nil")
	}

	noStatic := validConfig
	noStatic.StaticFS = nil
	if _, err := website.NewServer(noStatic); err == nil {
		t.Errorf("expected error when StaticFS is nil, got nil")
	}

	noDocs := validConfig
	noDocs.DocsFS = nil
	if _, err := website.NewServer(noDocs); err == nil {
		t.Errorf("expected error when DocsFS is nil, got nil")
	}

	noVuln := validConfig
	noVuln.Stores.Vuln = nil
	if _, err := website.NewServer(noVuln); err == nil {
		t.Errorf("expected error when Stores.Vuln is nil, got nil")
	}

	noRelations := validConfig
	noRelations.Stores.Relations = nil
	if _, err := website.NewServer(noRelations); err == nil {
		t.Errorf("expected error when Stores.Relations is nil, got nil")
	}

	noSourceRepo := validConfig
	noSourceRepo.Stores.SourceRepo = nil
	if _, err := website.NewServer(noSourceRepo); err == nil {
		t.Errorf("expected error when Stores.SourceRepo is nil, got nil")
	}

	noVulnSearch := validConfig
	noVulnSearch.Stores.VulnSearch = nil
	if _, err := website.NewServer(noVulnSearch); err == nil {
		t.Errorf("expected error when Stores.VulnSearch is nil, got nil")
	}

	noLinter := validConfig
	noLinter.Stores.Linter = nil
	if _, err := website.NewServer(noLinter); err == nil {
		t.Errorf("expected error when Stores.Linter is nil, got nil")
	}

	noTriage := validConfig
	noTriage.Stores.Triage = nil
	if _, err := website.NewServer(noTriage); err == nil {
		t.Errorf("expected error when Stores.Triage is nil, got nil")
	}
}

func TestHealthz(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{})
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()

	srv.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected status 200 OK, got %d", rec.Code)
	}
	if body := rec.Body.String(); body != "OK" {
		t.Errorf("expected body 'OK', got %q", body)
	}
}

func TestGoVanityImports(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{})

	t.Run("Root go-get=1", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/?go-get=1", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		expectedMeta := `<meta name="go-import" content="osv.dev git https://github.com/google/osv.dev">`
		if rec.Body.String() != expectedMeta {
			t.Errorf("expected body %q, got %q", expectedMeta, rec.Body.String())
		}
	})

	t.Run("Bindings go-get=1", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/bindings/go?go-get=1", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		expectedMeta := `<meta name="go-import" content="osv.dev git https://github.com/google/osv.dev">`
		if rec.Body.String() != expectedMeta {
			t.Errorf("expected body %q, got %q", expectedMeta, rec.Body.String())
		}
	})

	t.Run("Bindings redirect without go-get", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/bindings/go", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		expectedLoc := "https://pkg.go.dev/osv.dev/bindings/go"
		if loc := rec.Header().Get("Location"); loc != expectedLoc {
			t.Errorf("expected Location header %q, got %q", expectedLoc, loc)
		}
	})
}

func TestRedirects(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{})

	tests := []struct {
		path        string
		expectedLoc string
	}{
		{"/about", "https://google.github.io/osv.dev/faq"},
		{"/faq", "https://google.github.io/osv.dev/faq"},
		{"/docs", "https://google.github.io/osv.dev"},
		{"/ecosystems", "https://storage.googleapis.com/osv-vulnerabilities/ecosystems.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(http.MethodGet, tt.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != http.StatusFound {
				t.Errorf("expected status 302 Found for %s, got %d", tt.path, rec.Code)
			}
			if loc := rec.Header().Get("Location"); loc != tt.expectedLoc {
				t.Errorf("expected Location %q for %s, got %q", tt.expectedLoc, tt.path, loc)
			}
		})
	}
}

func TestPublicKeys(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	keysDir := filepath.Join(tmpDir, "public_keys")
	if err := os.MkdirAll(keysDir, 0755); err != nil {
		t.Fatalf("failed to create temp keys dir: %v", err)
	}

	keyFile := filepath.Join(keysDir, "test.pub")
	if err := os.WriteFile(keyFile, []byte("PUBLIC KEY DATA"), 0600); err != nil {
		t.Fatalf("failed to write test key file: %v", err)
	}

	srv := newTestServer(t, website.Config{StaticFS: os.DirFS(tmpDir)})

	t.Run("Existing public key", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/public_keys/test.pub", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if body := rec.Body.String(); body != "PUBLIC KEY DATA" {
			t.Errorf("expected body 'PUBLIC KEY DATA', got %q", body)
		}
	})

	t.Run("Non-existent key", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/public_keys/missing.pub", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})

	t.Run("Path traversal prevention", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/public_keys/../test.pub", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound && rec.Code != http.StatusTemporaryRedirect && rec.Code != http.StatusMovedPermanently {
			t.Errorf("expected status 400, 404, 307, or 301, got %d", rec.Code)
		}
	})
}

func TestStaticFiles(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	imgDir := filepath.Join(tmpDir, "static", "img")
	if err := os.MkdirAll(imgDir, 0755); err != nil {
		t.Fatalf("failed to create static img dir: %v", err)
	}

	goDir := filepath.Join(tmpDir, "go")
	if err := os.MkdirAll(goDir, 0755); err != nil {
		t.Fatalf("failed to create go dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "base.html"), []byte(`<html>{{ block "content" . }}{{ end }}</html>`), 0600); err != nil {
		t.Fatalf("failed to write base.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "home.html"), []byte(`{{ define "content" }}Home{{ end }}`), 0600); err != nil {
		t.Fatalf("failed to write home.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "404.html"), []byte(`{{ define "content" }}404 {{ .FailedImportVulnID }}{{ end }}`), 0600); err != nil {
		t.Fatalf("failed to write 404.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(imgDir, "favicon-32x32.png"), []byte("FAVICON"), 0600); err != nil {
		t.Fatalf("failed to write favicon: %v", err)
	}

	blogDir := filepath.Join(tmpDir, "static", "blog")
	postDir := filepath.Join(blogDir, "posts", "hello-world")
	if err := os.MkdirAll(postDir, 0755); err != nil {
		t.Fatalf("failed to create blog post dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "blog.html"), []byte(`{{ define "content" }}Blog Index: {{ .Index }}{{ end }}`), 0600); err != nil {
		t.Fatalf("failed to write blog.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "blog_post.html"), []byte(`{{ define "content" }}Blog Post: {{ .Content }}{{ end }}`), 0600); err != nil {
		t.Fatalf("failed to write blog_post.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blogDir, "index.html"), []byte("<h1>Blog Index</h1>"), 0600); err != nil {
		t.Fatalf("failed to write blog index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(blogDir, "index.xml"), []byte("<rss>RSS</rss>"), 0600); err != nil {
		t.Fatalf("failed to write blog rss: %v", err)
	}
	if err := os.WriteFile(filepath.Join(postDir, "index.html"), []byte("<article>Hello World</article>"), 0600); err != nil {
		t.Fatalf("failed to write blog post content: %v", err)
	}
	if err := os.WriteFile(filepath.Join(postDir, "hero.png"), []byte("PNG_DATA"), 0600); err != nil {
		t.Fatalf("failed to write blog post image asset: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "triage.html"), []byte(`{{ define "content" }}Triage{{ end }}`), 0600); err != nil {
		t.Fatalf("failed to write triage.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "vulnerability.html"), []byte(`{{ define "content" }}Vulnerability {{ .Vulnerability.Id }}{{ end }}`), 0600); err != nil {
		t.Fatalf("failed to write vulnerability.html: %v", err)
	}
	if err := os.WriteFile(filepath.Join(goDir, "linter.html"), []byte(`Linter Report`), 0600); err != nil {
		t.Fatalf("failed to write linter.html: %v", err)
	}

	srv := newTestServer(t, website.Config{StaticFS: os.DirFS(tmpDir)})

	t.Run("Vulnerability_details_page", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/vulnerability/GHSA-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Vulnerability_details_single_alias_redirect", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/vulnerability/ALIAS-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/vulnerability/GHSA-1234" {
			t.Errorf("expected Location '/vulnerability/GHSA-1234', got %q", loc)
		}
	})

	t.Run("Triage_page", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/triage", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Linter_page", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Blog_index", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/blog", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Blog_rss_serves_xml", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/blog/index.xml", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if contentType := rec.Header().Get("Content-Type"); contentType != "application/xml; charset=utf-8" {
			t.Errorf("expected content-type 'application/xml; charset=utf-8', got %q", contentType)
		}
	})

	t.Run("Blog_post", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/blog/posts/hello-world/", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("Blog_post_asset_serves_file", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/blog/posts/hello-world/hero.png", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if rec.Body.String() != "PNG_DATA" {
			t.Errorf("expected body 'PNG_DATA', got %q", rec.Body.String())
		}
	})

	t.Run("Blog_post_asset_invalid_base", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/blog/posts/hello-world/..", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound && rec.Code != http.StatusBadRequest && rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusTemporaryRedirect {
			t.Errorf("expected status 404, 400, 301, or 307, got %d", rec.Code)
		}
	})

	t.Run("Root", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("renderNotFound", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/404", nil)
		rec := httptest.NewRecorder()
		srv.RenderNotFound(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})

	t.Run("renderNotFoundWithVuln", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/404", nil)
		rec := httptest.NewRecorder()
		srv.RenderNotFoundWithVuln(rec, req, "GHSA-1234")

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})

	t.Run("UnmatchedRoute_returns_404", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/foo/bar", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})

	t.Run("Favicon", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/favicon.ico", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if rec.Body.String() != "FAVICON" {
			t.Errorf("expected body 'FAVICON', got %q", rec.Body.String())
		}
	})

	t.Run("Robots.txt", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/robots.txt", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if !strings.HasPrefix(rec.Body.String(), "Sitemap: ") {
			t.Errorf("expected Sitemap header in body, got %q", rec.Body.String())
		}
	})
}

func TestPotentialVulnerability(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{})

	t.Run("Existing vuln redirects to /vulnerability/{id}", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/GHSA-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/vulnerability/GHSA-1234" {
			t.Errorf("expected Location '/vulnerability/GHSA-1234', got %q", loc)
		}
	})

	t.Run("Single alias vuln redirects to /vulnerability/{canonical_id}", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/ALIAS-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/vulnerability/GHSA-1234" {
			t.Errorf("expected Location '/vulnerability/GHSA-1234', got %q", loc)
		}
	})

	t.Run("Non-existent vuln falls back to /list?q={id}", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/UNKNOWN-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/list?q=UNKNOWN-1234" {
			t.Errorf("expected Location '/list?q=UNKNOWN-1234', got %q", loc)
		}
	})

	t.Run("Invalid vuln ID returns 404 Not Found", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/$invalid_id$", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})
}

func TestVulnerabilityJSON(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{
		APIURL: "api.osv.dev",
	})

	t.Run("Existing vuln from /vulnerability/{id}.json redirects to api.osv.dev", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/vulnerability/GHSA-1234.json", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://api.osv.dev/v1/vulns/GHSA-1234" {
			t.Errorf("expected Location 'https://api.osv.dev/v1/vulns/GHSA-1234', got %q", loc)
		}
	})

	t.Run("Existing vuln from /{id}.json redirects to api.osv.dev", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/GHSA-1234.json", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://api.osv.dev/v1/vulns/GHSA-1234" {
			t.Errorf("expected Location 'https://api.osv.dev/v1/vulns/GHSA-1234', got %q", loc)
		}
	})

	t.Run("Non-existent vuln returns 404", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/vulnerability/UNKNOWN-1234.json", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})
}

func TestAuthEndpoints(t *testing.T) {
	t.Parallel()

	t.Run("GET /login with BypassOAuth sets cookie and redirects to /triage", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/triage" {
			t.Errorf("expected Location '/triage', got %q", loc)
		}
		cookies := rec.Result().Cookies()
		if len(cookies) == 0 || cookies[0].Name != "osv_session" {
			t.Errorf("expected session cookie to be set")
		}
	})

	t.Run("GET /login without credentials returns 500 JSON", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				ClientID: "missing-client-secret",
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", rec.Code)
		}
	})

	t.Run("GET /login with credentials redirects to Google OAuth and sets state cookie", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/login", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		loc := rec.Header().Get("Location")
		if !strings.HasPrefix(loc, "https://accounts.google.com/o/oauth2/auth") && !strings.HasPrefix(loc, "https://accounts.google.com/o/oauth2/v2/auth") {
			t.Errorf("expected Location to start with Google auth URL, got %q", loc)
		}
		cookies := rec.Result().Cookies()
		var stateCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "osv_oauth_state" {
				stateCookie = c
				break
			}
		}
		if stateCookie == nil || stateCookie.Value == "" {
			t.Errorf("expected osv_oauth_state cookie to be set")
		}
	})

	t.Run("GET /auth/callback with mismatched state returns 400", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{})
		req := httptest.NewRequest(http.MethodGet, "/auth/callback?state=invalid-state", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("GET /logout clears session cookie and redirects", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{})
		req := httptest.NewRequest(http.MethodGet, "/logout", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/triage" {
			t.Errorf("expected Location '/triage', got %q", loc)
		}
		cookies := rec.Result().Cookies()
		for _, c := range cookies {
			if c.Name == "osv_session" && c.MaxAge != -1 {
				t.Errorf("expected osv_session cookie to be cleared (MaxAge=-1), got %d", c.MaxAge)
			}
		}
	})
}

func TestTriageEndpoints(t *testing.T) {
	t.Parallel()

	t.Run("GET /triage without auth redirects to /login", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("expected Location '/login', got %q", loc)
		}
	})

	t.Run("GET /triage with valid session cookie renders 200 OK", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
				SecretKey:    "test-secret-key-12345",
			},
		})

		// First log in with bypass to get a valid session cookie
		bypassSrv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
				SecretKey:   "test-secret-key-12345",
			},
		})
		loginReq := httptest.NewRequest(http.MethodGet, "/login", nil)
		loginRec := httptest.NewRecorder()
		bypassSrv.ServeHTTP(loginRec, loginReq)

		cookies := loginRec.Result().Cookies()
		var sessionCookie *http.Cookie
		for _, c := range cookies {
			if c.Name == "osv_session" {
				sessionCookie = c
				break
			}
		}
		if sessionCookie == nil {
			t.Fatalf("expected session cookie from login")
		}

		req := httptest.NewRequest(http.MethodGet, "/triage", nil)
		req.AddCookie(sessionCookie)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK with valid cookie, got %d", rec.Code)
		}
	})

	t.Run("GET /triage with invalid session cookie redirects to /login", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				ClientID:     "test-client-id",
				ClientSecret: "test-client-secret",
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage", nil)
		req.AddCookie(&http.Cookie{
			Name:  "osv_session",
			Value: "tampered-or-invalid-cookie",
		})
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "/login" {
			t.Errorf("expected Location '/login', got %q", loc)
		}
	})

	t.Run("GET /triage with BypassOAuth renders 200 OK", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("GET /triage/proxy fetches file successfully", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage/proxy?source=test-nvd&id=CVE-2024-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		if rec.Body.String() != `{"id":"CVE-2024-1234"}` {
			t.Errorf("unexpected response body: %s", rec.Body.String())
		}
	})

	t.Run("GET /triage/proxy with missing params returns 400", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage/proxy", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("GET /triage/proxy with invalid CVE ID format returns 400", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage/proxy?source=test-nvd&id=INVALID", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("GET /triage/proxy with invalid source returns 400", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage/proxy?source=invalid-source&id=CVE-2024-1234", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusBadRequest {
			t.Errorf("expected status 400 Bad Request, got %d", rec.Code)
		}
	})

	t.Run("GET /triage/proxy with non-existent CVE returns 404", func(t *testing.T) {
		t.Parallel()
		srv := newTestServer(t, website.Config{
			Auth: website.AuthConfig{
				BypassOAuth: true,
			},
		})
		req := httptest.NewRequest(http.MethodGet, "/triage/proxy?source=test-nvd&id=CVE-2024-9999", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})
}

func TestLinterEndpoints(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{})

	t.Run("GET /linter renders successfully", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
	})

	t.Run("GET /linter on osv.dev redirects to test.osv.dev", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter", nil)
		req.Host = "OSV.DEV:443"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://test.osv.dev/linter" {
			t.Errorf("expected Location 'https://test.osv.dev/linter', got %q", loc)
		}
	})

	t.Run("GET /linter-findings returns sources JSON", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter-findings", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		expectedBody := "[\"cve-osv\",\"ghsa\"]\n"
		if rec.Body.String() != expectedBody {
			t.Errorf("expected body %q, got %q", expectedBody, rec.Body.String())
		}
	})

	t.Run("GET /linter-findings on osv.dev redirects to test.osv.dev", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter-findings", nil)
		req.Host = "osv.dev"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Errorf("expected status 302 Found, got %d", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://test.osv.dev/linter-findings" {
			t.Errorf("expected Location 'https://test.osv.dev/linter-findings', got %q", loc)
		}
	})

	t.Run("GET /linter-findings/{source} returns findings JSON", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter-findings/ghsa", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("expected Content-Type application/json, got %q", ct)
		}
		expectedBody := `{"findings":[]}`
		if rec.Body.String() != expectedBody {
			t.Errorf("expected body %q, got %q", expectedBody, rec.Body.String())
		}
	})

	t.Run("GET /linter-findings/{source} on unknown source returns 404", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/linter-findings/unknown-source", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Errorf("expected status 404 Not Found, got %d", rec.Code)
		}
	})
}
