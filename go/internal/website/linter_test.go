package website_test

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/website"
)

type richLinterStore struct {
	models.UnimplementedLinterStore

	mu          sync.Mutex
	infos       []models.LinterSourceInfo
	payloads    map[string]string
	fetchCounts map[string]int
}

func (s *richLinterStore) ListSources(_ context.Context) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	names := make([]string, len(s.infos))
	for i, info := range s.infos {
		names[i] = info.Source
	}

	return names, nil
}

func (s *richLinterStore) ListSourceInfos(_ context.Context) ([]models.LinterSourceInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return slices.Clone(s.infos), nil
}

func (s *richLinterStore) GetFindings(_ context.Context, source string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetchCounts != nil {
		s.fetchCounts[source]++
	}
	raw, ok := s.payloads[source]
	if !ok {
		return nil, models.ErrNotFound
	}

	return []byte(raw), nil
}

type richSourceRepoStore struct {
	models.UnimplementedSourceRepositoryStore

	names []string
}

func (s richSourceRepoStore) Get(_ context.Context, name string) (*models.SourceRepository, error) {
	if slices.Contains(s.names, name) {
		return &models.SourceRepository{Name: name}, nil
	}

	return nil, models.ErrNotFound
}

func (s richSourceRepoStore) All(_ context.Context) iter.Seq2[*models.SourceRepository, error] {
	return func(yield func(*models.SourceRepository, error) bool) {
		for _, n := range s.names {
			if !yield(&models.SourceRepository{Name: n}, nil) {
				return
			}
		}
	}
}

type richImportFindingsStore struct {
	models.UnimplementedImportFindingsStore

	findings []*models.ImportFinding
	err      error
}

func (s richImportFindingsStore) ListAll(_ context.Context) ([]*models.ImportFinding, error) {
	if s.err != nil {
		return nil, s.err
	}

	return s.findings, nil
}

func setupLinterTestServer(t *testing.T) (*website.Server, *richLinterStore) {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)

	linterStore := &richLinterStore{
		infos: []models.LinterSourceInfo{
			{Source: "chainguard", Updated: now.Add(-1 * time.Hour), Generation: 100},
			{Source: "cve-osv", Updated: now.Add(-2 * time.Hour), Generation: 200},
			{Source: "ghsa", Updated: now.Add(-3 * time.Hour), Generation: 300},
		},
		payloads: map[string]string{
			"chainguard": `{
				"tmp/tmp/CGA-1111.json": [{"Code": "RNG:002", "Message": "Overlapping version event \"1.2.3\""}],
				"tmp/tmp/CGA-2222.json": [
					{"Code": "RNG:002", "Message": "Overlapping version event \"2.0.0\""},
					{"Code": "SCH:001", "Message": "Record does not conform to schema"}
				]
			}`,
			"cve-osv": `{
				"tmp/tmp/CVE-2026-0001.json": [
					{"Code": "REC:001", "Message": "Invalid Affected: empty"},
					{"Code": "REC:003", "Message": "Invalid Upstream: alias"},
					{"Code": "PKG:003", "Message": "Invalid PURL: pkg:maven/log4j"}
				]
			}`,
			"ghsa": `{
				"tmp/tmp/GHSA-aaaa-bbbb-cccc.json": [{"Code": "SCH:001", "Message": "Invalid URL naïve-example"}]
			}`,
		},
		fetchCounts: make(map[string]int),
	}

	importFindings := richImportFindingsStore{
		findings: []*models.ImportFinding{
			{BugID: "GHSA-aaaa-bbbb-cccc", Source: "ghsa", FirstSeen: now.Add(-6 * time.Hour), LastAttempt: now.Add(-10 * time.Minute)},
			{BugID: "CVE-2026-0001", Source: "cve-osv", FirstSeen: now.Add(-5 * 24 * time.Hour), LastAttempt: now.Add(-30 * time.Minute)},
			{BugID: "CGA-2222", Source: "chainguard", FirstSeen: now.Add(-20 * 24 * time.Hour), LastAttempt: now.Add(-45 * time.Minute)},
			{BugID: "CGA-1111", Source: "chainguard", FirstSeen: now.Add(-60 * 24 * time.Hour), LastAttempt: now.Add(-60 * time.Minute)},
		},
	}

	srv := newTestServer(t, website.Config{
		Stores: website.Stores{
			Linter:         linterStore,
			SourceRepo:     richSourceRepoStore{names: []string{"alpine", "chainguard", "cve-osv", "ghsa"}},
			ImportFindings: importFindings,
		},
	})

	return srv, linterStore
}

func queryLinter(t *testing.T, srv *website.Server, rawQuery string) website.LinterQueryResponse {
	t.Helper()
	target := "/linter-findings/query"
	if rawQuery != "" {
		target += "?" + rawQuery
	}
	req := httptest.NewRequest(http.MethodGet, target, nil)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s returned status %d: %s", target, rec.Code, rec.Body.String())
	}

	var resp website.LinterQueryResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed decoding LinterQueryResponse: %v", err)
	}

	return resp
}

func TestLinterQuery_PaginatedIndexAndEndpoints(t *testing.T) {
	t.Parallel()
	srv, _ := setupLinterTestServer(t)

	resp := queryLinter(t, srv, "")
	wantOrder := []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "CGA-2222", "CGA-1111"}
	gotOrder := []string{resp.Issues[0].BugID, resp.Issues[1].BugID, resp.Issues[2].BugID, resp.Issues[3].BugID}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("got order %v, want %v", gotOrder, wantOrder)
	}
	for _, issue := range resp.Issues {
		if len(issue.Details) == 0 {
			t.Errorf("expected inline Details on %s", issue.BugID)
		}
	}
	if !slices.ContainsFunc(resp.Facets.Sources, func(s website.LinterSourceFacet) bool { return s.Name == "alpine" && s.Count == 0 }) {
		t.Errorf("expected 0-count alpine in facets, got %+v", resp.Facets.Sources)
	}

	if got := queryLinter(t, srv, "source=chainguard"); got.Total != 2 {
		t.Errorf("expected 2 chainguard issues, got %d", got.Total)
	}
	if got := queryLinter(t, srv, "code=SCH:001"); got.Total != 2 {
		t.Errorf("expected 2 SCH:001 issues, got %d", got.Total)
	}
	if got := queryLinter(t, srv, "finding=IMPORT_FINDING_TYPE_INVALID_UPSTREAM"); got.Total != 1 || got.Issues[0].BugID != "CVE-2026-0001" {
		t.Errorf("unexpected legacy finding result: %+v", got.Issues)
	}
	if got := queryLinter(t, srv, "q=ghsa-aaaa"); got.Total != 1 {
		t.Errorf("expected 1 result for q=ghsa-aaaa, got %d", got.Total)
	}
	if got := queryLinter(t, srv, "order=asc"); got.Issues[0].BugID != "CGA-1111" {
		t.Errorf("expected CGA-1111 first for order=asc, got %s", got.Issues[0].BugID)
	}

	p1 := queryLinter(t, srv, "page=1&page_size=2")
	p2 := queryLinter(t, srv, "page=2&page_size=2")
	p99 := queryLinter(t, srv, "page=99&page_size=2")
	if p1.Page != 1 || len(p1.Issues) != 2 || p2.Page != 2 || len(p2.Issues) != 2 {
		t.Errorf("unexpected pagination pages: p1=(%d,%d) p2=(%d,%d)", p1.Page, len(p1.Issues), p2.Page, len(p2.Issues))
	}
	if p1.Issues[0].BugID == p2.Issues[0].BugID {
		t.Errorf("expected distinct issues across page 1 and page 2")
	}
	if p99.Page != 2 {
		t.Errorf("expected out-of-range page=99 to clamp to 2, got %d", p99.Page)
	}

	for _, tc := range []struct {
		path       string
		host       string
		wantStatus int
	}{
		{"/linter-findings/bug/CVE-2026-0001", "test.osv.dev", http.StatusOK},
		{"/linter-findings/bug/DOES-NOT-EXIST", "test.osv.dev", http.StatusNotFound},
		{"/linter-findings/vuln/CVE-2026-0001", "test.osv.dev", http.StatusOK},
		{"/linter-findings/query?source=ghsa", "osv.dev", http.StatusFound},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("GET %s (host %s) = %d, want %d", tc.path, tc.host, rec.Code, tc.wantStatus)
		}
	}
}

func TestLinterIndex_GenerationCaching(t *testing.T) {
	t.Parallel()
	srv, store := setupLinterTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	srv.StartLinterRefresh(ctx)
	_ = queryLinter(t, srv, "")

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.fetchCounts["chainguard"] != 1 {
		t.Errorf("expected chainguard fetch count 1, got %d", store.fetchCounts["chainguard"])
	}
}

func TestLinterIndex_TimestampEnrichmentErrorFallback(t *testing.T) {
	t.Parallel()

	linterStore := &richLinterStore{
		infos: []models.LinterSourceInfo{{Source: "ghsa", Generation: 1}},
		payloads: map[string]string{
			"ghsa": `{"tmp/tmp/GHSA-1.json": [{"Code": "SCH:001", "Message": "bad schema"}]}`,
		},
	}
	srv := newTestServer(t, website.Config{
		Stores: website.Stores{
			Linter:         linterStore,
			ImportFindings: richImportFindingsStore{err: errors.New("datastore unavailable")},
		},
	})

	resp := queryLinter(t, srv, "")
	if resp.TimestampsReady {
		t.Errorf("expected TimestampsReady=false when ImportFindings.ListAll fails")
	}
	if resp.Total != 1 || resp.Issues[0].BugID != "GHSA-1" {
		t.Errorf("expected GCS findings to still be served on timestamp error, got %+v", resp)
	}
}
