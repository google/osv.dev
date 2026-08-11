package website_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"

	"github.com/google/osv.dev/go/internal/website"
)

func TestList_RenderPage(t *testing.T) {
	t.Parallel()

	staticFS := fstest.MapFS{
		"go/base.html": &fstest.MapFile{
			Data: []byte(`<html>{{ template "content" . }}</html>`),
		},
		"go/list.html": &fstest.MapFile{
			Data: []byte(`{{ define "content" }}<div>List Page {{ .Query }}</div>{{ end }}`),
		},
	}

	srv := newTestServer(t, website.Config{StaticFS: staticFS})

	tests := []struct {
		name       string
		url        string
		headers    map[string]string
		wantStatus int
		wantLoc    string
	}{
		{
			name:       "Default list page",
			url:        "/list",
			wantStatus: http.StatusOK,
		},
		{
			name:       "List page with query and ecosystem filter",
			url:        "/list?q=requests&ecosystem=PyPI",
			wantStatus: http.StatusOK,
		},
		{
			name:       "Direct full page load with page parameter redirects",
			url:        "/list?q=requests&page=2",
			wantStatus: http.StatusFound,
			wantLoc:    "/list?q=requests",
		},
		{
			name:       "Turbo-Frame load with page parameter returns OK",
			url:        "/list?q=requests&page=2",
			headers:    map[string]string{"Turbo-Frame": "vulnerability-table-page2"},
			wantStatus: http.StatusOK,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			for k, v := range tt.headers {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf("GET %s returned status %d, want %d (body: %s)", tt.url, rec.Code, tt.wantStatus, rec.Body.String())
			}
			if tt.wantLoc != "" && rec.Header().Get("Location") != tt.wantLoc {
				t.Errorf("GET %s returned Location %q, want %q", tt.url, rec.Header().Get("Location"), tt.wantLoc)
			}
		})
	}
}
