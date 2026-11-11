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
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type richLinterStore struct {
	models.UnimplementedLinterStore

	mu          sync.Mutex
	infos       []models.LinterSourceInfo
	payloads    map[string]string
	fetchCounts map[string]int
	onFetch     func(source string)
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
	if s.fetchCounts != nil {
		s.fetchCounts[source]++
	}
	hook := s.onFetch
	raw, ok := s.payloads[source]
	s.mu.Unlock()

	if hook != nil {
		hook(source)
	}
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
	gate     <-chan struct{}
}

func (s richImportFindingsStore) ListAll(ctx context.Context) ([]*models.ImportFinding, error) {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return s.findings, nil
}

type linterVulnStore struct {
	models.UnimplementedVulnerabilityStore
}

func (linterVulnStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if id == "DOES-NOT-EXIST" {
		return nil, models.ErrNotFound
	}

	return &osvschema.Vulnerability{
		Id:            id,
		SchemaVersion: "1.6.0",
		Summary:       "Test vulnerability summary",
	}, nil
}

func setupLinterTestServerWithConfig(t *testing.T, ttl time.Duration) (*website.Server, *richLinterStore) {
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
			// CGA-1111 and CGA-2222 share the exact same LastAttempt timestamp to exercise BugID tie-breaking.
			{BugID: "CGA-2222", Source: "chainguard", FirstSeen: now.Add(-20 * 24 * time.Hour), LastAttempt: now.Add(-45 * time.Minute)},
			{BugID: "CGA-1111", Source: "chainguard", FirstSeen: now.Add(-60 * 24 * time.Hour), LastAttempt: now.Add(-45 * time.Minute)},
		},
	}

	srv := newTestServer(t, website.Config{
		LinterCacheTTL: ttl,
		Stores: website.Stores{
			Vuln:           linterVulnStore{},
			Linter:         linterStore,
			SourceRepo:     richSourceRepoStore{names: []string{"alpine", "chainguard", "cve-osv", "ghsa"}},
			ImportFindings: importFindings,
		},
	})

	return srv, linterStore
}

func setupLinterTestServer(t *testing.T) (*website.Server, *richLinterStore) {
	t.Helper()
	return setupLinterTestServerWithConfig(t, 0)
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
	// CGA-1111 and CGA-2222 tie on LastAttempt (-45m) and sort ascending by BugID.
	wantOrder := []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "CGA-1111", "CGA-2222"}
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

	// Filtering & search.
	if got := queryLinter(t, srv, "source=chainguard"); got.Total != 2 {
		t.Errorf("expected 2 chainguard issues, got %d", got.Total)
	}
	if got := queryLinter(t, srv, "code=SCH:001"); got.Total != 2 {
		t.Errorf("expected 2 SCH:001 issues, got %d", got.Total)
	}
	if got := queryLinter(t, srv, "q=ghsa-aaaa"); got.Total != 1 {
		t.Errorf("expected 1 result for q=ghsa-aaaa, got %d", got.Total)
	}
	if got := queryLinter(t, srv, "q=nomatch"); got.Total != 0 || len(got.Issues) != 0 {
		t.Errorf("expected 0 results for q=nomatch, got total=%d issues=%v", got.Total, got.Issues)
	}
	if got := queryLinter(t, srv, "order=asc"); got.Issues[0].BugID != "CGA-1111" || got.Issues[1].BugID != "CGA-2222" {
		t.Errorf("expected CGA-1111 then CGA-2222 first for order=asc, got %v", got.Issues)
	}

	// Dynamic cross-facet counts when both source and code filters are active.
	cross := queryLinter(t, srv, "source=chainguard&code=SCH:001")
	if cross.Total != 1 || cross.Issues[0].BugID != "CGA-2222" {
		t.Errorf("unexpected combined filter result: %+v", cross)
	}
	if cross.Facets.TotalForSources != 2 {
		t.Errorf("expected TotalForSources=2 (chainguard + ghsa matching SCH:001), got %d", cross.Facets.TotalForSources)
	}
	if cross.Facets.TotalForRules != 2 {
		t.Errorf("expected TotalForRules=2 (2 chainguard issues), got %d", cross.Facets.TotalForRules)
	}

	// Pagination slicing & clamping boundaries.
	p1 := queryLinter(t, srv, "page=1&page_size=2")
	if p1.Page != 1 || p1.PageSize != 2 || len(p1.Issues) != 2 || p1.Issues[0].BugID != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("unexpected page 1 response: %+v", p1)
	}
	p2 := queryLinter(t, srv, "page=2&page_size=2")
	if p2.Page != 2 || len(p2.Issues) != 2 || p2.Issues[0].BugID != "CGA-1111" {
		t.Errorf("unexpected page 2 response: %+v", p2)
	}
	clampedHigh := queryLinter(t, srv, "page=99&page_size=2")
	if clampedHigh.Page != 2 || len(clampedHigh.Issues) != 2 || clampedHigh.Issues[0].BugID != "CGA-1111" {
		t.Errorf("expected page=99 to clamp to page 2, got %+v", clampedHigh)
	}
	clampedBounds := queryLinter(t, srv, "page=-1&page_size=500")
	if clampedBounds.Page != 1 || clampedBounds.PageSize != 100 {
		t.Errorf("expected page=1 pageSize=100, got page=%d pageSize=%d", clampedBounds.Page, clampedBounds.PageSize)
	}

	// Vulnerability JSON endpoint & host redirects.
	for _, tc := range []struct {
		path       string
		host       string
		wantStatus int
	}{
		{"/linter-findings/vuln/CVE-2026-0001", "test.osv.dev", http.StatusOK},
		{"/linter-findings/vuln/DOES-NOT-EXIST", "test.osv.dev", http.StatusNotFound},
		{"/linter-findings/vuln/bad$id!", "test.osv.dev", http.StatusNotFound},
		{"/linter-findings/query?source=ghsa", "osv.dev", http.StatusFound},
		{"/linter-findings/query?source=ghsa", "api.osv.dev", http.StatusFound},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("GET %s (host %s) = %d, want %d", tc.path, tc.host, rec.Code, tc.wantStatus)
		}
		if tc.path == "/linter-findings/vuln/CVE-2026-0001" && rec.Code == http.StatusOK {
			var payload map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
				t.Fatalf("failed decoding vuln protojson: %v", err)
			}
			if payload["id"] != "CVE-2026-0001" || payload["schema_version"] != "1.6.0" {
				t.Errorf("unexpected protojson payload (want snake_case proto names): %v", payload)
			}
		}
	}
}

func TestLinterIndex_GenerationCaching(t *testing.T) {
	t.Parallel()
	srv, store := setupLinterTestServerWithConfig(t, 10*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go srv.StartLinterRefresh(ctx)

	// Initial query populates all 3 sources once.
	initial := queryLinter(t, srv, "")
	if initial.Total != 4 {
		t.Fatalf("expected 4 initial issues, got %d", initial.Total)
	}

	// Wait for TTL to expire and trigger a second refresh with NO generation changes.
	time.Sleep(20 * time.Millisecond)
	unchanged := queryLinter(t, srv, "")
	if unchanged.Total != 4 {
		t.Fatalf("expected 4 issues on unchanged refresh, got %d", unchanged.Total)
	}

	store.mu.Lock()
	if store.fetchCounts["chainguard"] != 1 || store.fetchCounts["cve-osv"] != 1 || store.fetchCounts["ghsa"] != 1 {
		t.Fatalf("expected all fetchCounts == 1 after generation cache hit, got %v", store.fetchCounts)
	}
	// Bump only cve-osv's generation and add a second bug.
	store.infos[1].Generation = 201
	store.infos[1].Updated = store.infos[1].Updated.Add(time.Minute)
	store.payloads["cve-osv"] = `{
		"tmp/tmp/CVE-2026-0001.json": [{"Code": "REC:001", "Message": "Invalid Affected: empty"}],
		"tmp/tmp/CVE-2026-0002.json": [{"Code": "SCH:001", "Message": "New schema error"}]
	}`
	store.mu.Unlock()

	time.Sleep(20 * time.Millisecond)
	updated := queryLinter(t, srv, "")
	if updated.Total != 5 {
		t.Fatalf("expected 5 issues after cve-osv generation bump, got %d", updated.Total)
	}

	store.mu.Lock()
	defer store.mu.Unlock()
	if store.fetchCounts["chainguard"] != 1 || store.fetchCounts["ghsa"] != 1 {
		t.Errorf("expected unchanged sources to remain at fetchCount 1, got %v", store.fetchCounts)
	}
	if store.fetchCounts["cve-osv"] != 2 {
		t.Errorf("expected bumped source cve-osv fetchCount 2, got %d", store.fetchCounts["cve-osv"])
	}
}

func TestLinterIndex_ColdStartFallbackAndProdRedirectConfig(t *testing.T) {
	t.Parallel()

	t.Run("serves GCS Updated fallback when ImportFindings enrichment exceeds cold grace wait", func(t *testing.T) {
		t.Parallel()
		gcsUpdated := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
		enrichedTime := time.Date(2026, 4, 2, 15, 30, 0, 0, time.UTC)
		gate := make(chan struct{})

		linterStore := &richLinterStore{
			infos: []models.LinterSourceInfo{
				{Source: "ghsa", Updated: gcsUpdated, Generation: 10},
			},
			payloads: map[string]string{
				"ghsa": `{"tmp/GHSA-slow-init.json": [{"Code": "SCH:001", "Message": "bad json"}]}`,
			},
		}
		srv := newTestServer(t, website.Config{
			Stores: website.Stores{
				Linter:     linterStore,
				SourceRepo: richSourceRepoStore{names: []string{"ghsa"}},
				ImportFindings: richImportFindingsStore{
					gate: gate,
					findings: []*models.ImportFinding{
						{BugID: "GHSA-slow-init", Source: "ghsa", LastAttempt: enrichedTime},
					},
				},
			},
		})

		coldResp := queryLinter(t, srv, "")
		if len(coldResp.Issues) != 1 || coldResp.Issues[0].LastAttempt != gcsUpdated.Format(time.RFC3339) {
			t.Fatalf("expected cold-start GCS fallback timestamp %s, got %+v", gcsUpdated.Format(time.RFC3339), coldResp.Issues)
		}

		close(gate)
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			enrichedResp := queryLinter(t, srv, "")
			if len(enrichedResp.Issues) == 1 && enrichedResp.Issues[0].LastAttempt == enrichedTime.Format(time.RFC3339) {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
		t.Fatal("timed out waiting for background ImportFindings timestamp enrichment")
	})

	t.Run("RedirectLinterToTest redirects non-osv.dev hosts without touching LinterStore", func(t *testing.T) {
		t.Parallel()
		store := &richLinterStore{
			infos:       []models.LinterSourceInfo{{Source: "ghsa", Generation: 1}},
			payloads:    map[string]string{"ghsa": `{}`},
			fetchCounts: make(map[string]int),
		}
		srv := newTestServer(t, website.Config{
			RedirectLinterToTest: true,
			Stores: website.Stores{
				Linter: store,
			},
		})

		req := httptest.NewRequest(http.MethodGet, "/linter-findings/query?source=ghsa", nil)
		req.Host = "osv-website-xyz.a.run.app"
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)

		if rec.Code != http.StatusFound {
			t.Fatalf("got status %d, want 302 Found", rec.Code)
		}
		if loc := rec.Header().Get("Location"); loc != "https://test.osv.dev/linter-findings/query?source=ghsa" {
			t.Errorf("got Location %q, want https://test.osv.dev/linter-findings/query?source=ghsa", loc)
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if len(store.fetchCounts) != 0 {
			t.Errorf("expected 0 LinterStore fetches when RedirectLinterToTest is enabled, got %v", store.fetchCounts)
		}
	})

	t.Run("aborted HTTP caller does not cancel shared singleflight refresh", func(t *testing.T) {
		t.Parallel()
		fetchStarted := make(chan struct{})
		releaseFetch := make(chan struct{})
		var once sync.Once

		srv, store := setupLinterTestServer(t)
		store.onFetch = func(_ string) {
			once.Do(func() {
				close(fetchStarted)
				<-releaseFetch
			})
		}

		reqCtx, cancelReq := context.WithCancel(context.Background())
		abortedDone := make(chan int, 1)
		go func() {
			req := httptest.NewRequest(http.MethodGet, "/linter-findings/query", nil).WithContext(reqCtx)
			rec := httptest.NewRecorder()
			srv.ServeHTTP(rec, req)
			abortedDone <- rec.Code
		}()

		<-fetchStarted
		// Second viewer joins the in-flight refresh while the first caller aborts.
		viewerDone := make(chan website.LinterQueryResponse, 1)
		go func() {
			viewerDone <- queryLinter(t, srv, "")
		}()

		cancelReq()
		<-abortedDone
		close(releaseFetch)

		got := <-viewerDone
		if got.Total != 4 {
			t.Fatalf("expected all 4 issues preserved despite first caller aborting, got %d", got.Total)
		}
	})
}
