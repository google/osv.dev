package website_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/osv.dev/go/internal/website"
)

func newTestServer(t *testing.T, cfg website.Config) *website.Server {
	t.Helper()
	if cfg.StaticFS == nil {
		cfg.StaticFS = fstest.MapFS{}
	}
	if cfg.DocsFS == nil {
		cfg.DocsFS = fstest.MapFS{}
	}
	srv, err := website.NewServer(cfg)
	if err != nil {
		t.Fatalf("failed creating test server: %v", err)
	}

	return srv
}

func TestNewServer_NilFS(t *testing.T) {
	t.Parallel()

	if _, err := website.NewServer(website.Config{}); err == nil {
		t.Errorf("expected error when StaticFS and DocsFS are nil, got nil")
	}
	if _, err := website.NewServer(website.Config{StaticFS: fstest.MapFS{}}); err == nil {
		t.Errorf("expected error when DocsFS is nil, got nil")
	}
	if _, err := website.NewServer(website.Config{DocsFS: fstest.MapFS{}}); err == nil {
		t.Errorf("expected error when StaticFS is nil, got nil")
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
	if err := os.WriteFile(filepath.Join(imgDir, "favicon-32x32.png"), []byte("FAVICON"), 0600); err != nil {
		t.Fatalf("failed to write favicon: %v", err)
	}

	srv := newTestServer(t, website.Config{StaticFS: os.DirFS(tmpDir)})

	t.Run("Root", func(t *testing.T) {
		t.Parallel()
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Errorf("expected status 200 OK, got %d", rec.Code)
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

func TestEndpointRegistration(t *testing.T) {
	t.Parallel()

	srv := newTestServer(t, website.Config{})

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/blog"},
		{http.MethodGet, "/blog/"},
		{http.MethodGet, "/blog/index.xml"},
		{http.MethodGet, "/blog/posts/test-post"},
		{http.MethodGet, "/blog/posts/test-post/"},
		{http.MethodGet, "/blog/posts/test-post/image.png"},
		{http.MethodGet, "/vulnerability/GHSA-1234"},
		{http.MethodGet, "/GHSA-1234"},
		{http.MethodGet, "/vulnerability/GHSA-1234.json"},
		{http.MethodGet, "/GHSA-1234.json"},
		{http.MethodGet, "/list"},
		{http.MethodGet, "/api/search_suggestions"},
		{http.MethodGet, "/linter"},
		{http.MethodGet, "/linter/"},
		{http.MethodGet, "/linter-findings"},
		{http.MethodGet, "/linter-findings/"},
		{http.MethodGet, "/linter-findings/test-source"},
		{http.MethodGet, "/triage"},
		{http.MethodPost, "/triage/proxy"},
		{http.MethodGet, "/login"},
		{http.MethodGet, "/auth/callback"},
		{http.MethodGet, "/logout"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			t.Parallel()
			req := httptest.NewRequest(ep.method, ep.path, nil)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code == http.StatusNotFound {
				t.Errorf("expected route %s %s to be registered, got 404 Not Found", ep.method, ep.path)
			}
		})
	}
}
