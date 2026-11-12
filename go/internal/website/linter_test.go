package website_test

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/website"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

type richLinterStore struct {
	models.UnimplementedLinterStore

	mu             sync.Mutex
	infos          []models.LinterSourceInfo
	payloads       map[string]string
	fetchCounts    map[string]int
	listInfosCount int
	listErr        error
	fetchErrs      map[string]error
}

func (s *richLinterStore) ListSourceInfos(_ context.Context) ([]models.LinterSourceInfo, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.listInfosCount++
	if s.listErr != nil {
		return nil, s.listErr
	}

	return slices.Clone(s.infos), nil
}

func (s *richLinterStore) GetFindings(_ context.Context, source string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetchCounts != nil {
		s.fetchCounts[source]++
	}
	if s.fetchErrs != nil && s.fetchErrs[source] != nil {
		return nil, s.fetchErrs[source]
	}
	raw, ok := s.payloads[source]
	if !ok {
		return nil, models.ErrNotFound
	}

	return []byte(raw), nil
}

type richSourceRepoStore struct {
	models.UnimplementedSourceRepositoryStore

	names   []string
	iterErr error
}

func (s *richSourceRepoStore) All(_ context.Context) iter.Seq2[*models.SourceRepository, error] {
	return func(yield func(*models.SourceRepository, error) bool) {
		if s.iterErr != nil {
			yield(nil, s.iterErr)
			return
		}
		for _, n := range s.names {
			if !yield(&models.SourceRepository{Name: n}, nil) {
				return
			}
		}
	}
}

type richImportFindingsStore struct {
	models.UnimplementedImportFindingsStore

	findings  map[string]int64
	firstSeen map[string]int64
	err       error
	gate      <-chan struct{}
}

func (s richImportFindingsStore) ListLastAttempts(ctx context.Context) (map[string]int64, error) {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}

	return s.findings, nil
}

func (s richImportFindingsStore) ListFirstSeen(ctx context.Context) (map[string]int64, error) {
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}

	return s.firstSeen, nil
}

type linterVulnStore struct {
	models.UnimplementedVulnerabilityStore
}

func (linterVulnStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	switch id {
	case "DOES-NOT-EXIST":
		return nil, models.ErrNotFound
	case "BACKEND-FAILURE":
		return nil, errors.New("datastore unavailable")
	default:
		return &osvschema.Vulnerability{Id: id, SchemaVersion: "1.6.0", Summary: "Test summary"}, nil
	}
}

func setupLinterTestServer(t *testing.T, ttl time.Duration) (*website.Server, *richLinterStore, *richSourceRepoStore) {
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
				"tmp/tmp/CGA-1111.json": [{"Code": "RNG:002", "Message": "Overlapping version event"}],
				"tmp/tmp/CGA-2222.json": [
					{"Code": "RNG:002", "Message": "Overlapping version event"},
					{"Code": "SCH:001", "Message": "Record does not conform to schema"}
				]
			}`,
			"cve-osv": `{"tmp/tmp/CVE-2026-0001.json": [
				{"Code": "REC:001", "Message": "Invalid Affected"},
				{"Code": "PKG:003", "Message": "Invalid PURL"}
			]}`,
			"ghsa": `{"tmp/tmp/GHSA-aaaa-bbbb-cccc.json": [{"Code": "SCH:001", "Message": "Invalid URL (naïve encoding)"}]}`,
		},
		fetchCounts: make(map[string]int),
		fetchErrs:   make(map[string]error),
	}
	sourceRepos := &richSourceRepoStore{names: []string{"alpine", "chainguard", "cve-osv", "ghsa"}}
	importFindings := richImportFindingsStore{
		findings: map[string]int64{
			"GHSA-aaaa-bbbb-cccc": now.Add(-10 * time.Minute).Unix(),
			"CVE-2026-0001":       now.Add(-30 * time.Minute).Unix(),
			"CGA-2222":            now.Add(-45 * time.Minute).Unix(), // Ties with CGA-1111 to exercise BugID tie-breaking.
			"CGA-1111":            now.Add(-45 * time.Minute).Unix(),
		},
		firstSeen: map[string]int64{
			"GHSA-aaaa-bbbb-cccc": now.Add(-1 * time.Hour).Unix(),
			"CVE-2026-0001":       now.Add(-48 * time.Hour).Unix(),
			"CGA-2222":            now.Add(-72 * time.Hour).Unix(),
			"CGA-1111":            now.Add(-96 * time.Hour).Unix(),
		},
	}

	srv := newTestServer(t, website.Config{
		LinterCacheTTL: ttl,
		Stores: website.Stores{
			Vuln:           linterVulnStore{},
			Linter:         linterStore,
			SourceRepo:     sourceRepos,
			ImportFindings: importFindings,
		},
	})

	return srv, linterStore, sourceRepos
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
	srv, _, _ := setupLinterTestServer(t, 0)

	resp := queryLinter(t, srv, "")
	wantOrder := []string{"GHSA-aaaa-bbbb-cccc", "CVE-2026-0001", "CGA-1111", "CGA-2222"}
	gotOrder := []string{resp.Issues[0].BugID, resp.Issues[1].BugID, resp.Issues[2].BugID, resp.Issues[3].BugID}
	if !slices.Equal(gotOrder, wantOrder) {
		t.Fatalf("got order %v, want %v", gotOrder, wantOrder)
	}
	if !slices.ContainsFunc(resp.Facets.Sources, func(s website.LinterSourceFacet) bool { return s.Name == "alpine" && s.Count == 0 }) {
		t.Errorf("expected 0-count alpine in facets, got %+v", resp.Facets.Sources)
	}

	for _, tc := range []struct {
		query     string
		wantTotal int
		wantPage  int
		wantFirst string
	}{
		{"source=chainguard", 2, 1, "CGA-1111"},
		{"source=chainguard&order=asc", 2, 1, "CGA-1111"},
		{"source=ghsa,cve-osv&source_mode=include", 2, 1, "GHSA-aaaa-bbbb-cccc"},
		{"source=chainguard&source_mode=exclude", 2, 1, "GHSA-aaaa-bbbb-cccc"},
		{"code=SCH:001", 2, 1, "GHSA-aaaa-bbbb-cccc"},
		{"cat=PKG", 1, 1, "CVE-2026-0001"},
		// Excluding RNG:002 hides CGA-1111 (RNG:002-only) while keeping CGA-2222 (also has SCH:001).
		{"code=RNG:002&rule_mode=exclude", 3, 1, "GHSA-aaaa-bbbb-cccc"},
		{"cat=RNG&rule_mode=exclude", 3, 1, "GHSA-aaaa-bbbb-cccc"},
		{"finding=IMPORT_FINDING_TYPE_INVALID_RECORD", 1, 1, "CVE-2026-0001"},
		{"q=ghsa-aaaa", 1, 1, "GHSA-aaaa-bbbb-cccc"},
		{"q=NAÏVE", 1, 1, "GHSA-aaaa-bbbb-cccc"},
		{"since=24h", 1, 1, "GHSA-aaaa-bbbb-cccc"},
		{"sort=finding_count&order=desc", 4, 1, "CGA-2222"},
		{"sort=first_seen&order=asc", 4, 1, "CGA-1111"},
		{"q=nomatch", 0, 1, ""},
		{"order=asc", 4, 1, "CGA-1111"},
		{"page=2&page_size=2", 4, 2, "CGA-1111"},
		{"page=99&page_size=2", 4, 2, "CGA-1111"},
		{"code=SCH:001&page=99&page_size=1", 2, 2, "CGA-2222"},
		{"page=-1&page_size=500", 4, 1, "GHSA-aaaa-bbbb-cccc"},
	} {
		got := queryLinter(t, srv, tc.query)
		if got.Total != tc.wantTotal || got.Page != tc.wantPage {
			t.Errorf("query(%q): got (total=%d, page=%d), want (%d, %d)", tc.query, got.Total, got.Page, tc.wantTotal, tc.wantPage)
		}
		if tc.wantFirst != "" && (len(got.Issues) == 0 || got.Issues[0].BugID != tc.wantFirst) {
			t.Errorf("query(%q): got first=%v, want %s", tc.query, got.Issues, tc.wantFirst)
		}
	}

	cross := queryLinter(t, srv, "source=chainguard&code=SCH:001")
	if cross.Total != 1 || cross.Facets.TotalForSources != 2 || cross.Facets.TotalForRules != 2 {
		t.Errorf("unexpected cross-facet totals: %+v", cross)
	}

	for _, tc := range []struct {
		path       string
		host       string
		wantStatus int
		wantID     string
	}{
		{"/linter-findings/vuln/CVE-2026-0001", "test.osv.dev", http.StatusOK, "CVE-2026-0001"},
		{"/linter-findings/vuln/SUSE-SU-2023%3A3313-1", "test.osv.dev", http.StatusOK, "SUSE-SU-2023:3313-1"},
		{"/linter-findings/vuln/DOES-NOT-EXIST", "test.osv.dev", http.StatusNotFound, ""},
		{"/linter-findings/vuln/BACKEND-FAILURE", "test.osv.dev", http.StatusInternalServerError, ""},
		{"/linter-findings/vuln/bad$id!", "test.osv.dev", http.StatusNotFound, ""},
		{"/linter-findings/vuln/", "test.osv.dev", http.StatusNotFound, ""},
		{"/linter-findings/query/", "test.osv.dev", http.StatusNotFound, ""},
		{"/linter-findings/query?source=ghsa", "osv.dev", http.StatusFound, ""},
		{"/linter-findings/query?source=ghsa", "api.osv.dev", http.StatusFound, ""},
	} {
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Host = tc.host
		rec := httptest.NewRecorder()
		srv.ServeHTTP(rec, req)
		if rec.Code != tc.wantStatus {
			t.Errorf("GET %s (host %s) = %d, want %d", tc.path, tc.host, rec.Code, tc.wantStatus)
		}
		if tc.wantID != "" && !strings.Contains(rec.Body.String(), `"id":"`+tc.wantID+`"`) {
			t.Errorf("GET %s body missing id %q: %s", tc.path, tc.wantID, rec.Body.String())
		}
	}
}

func TestLinterPageAndRedirectConfig(t *testing.T) {
	t.Parallel()

	tmplBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "website", "frontend3", "src", "templates", "linter", "index.html"))
	if err != nil {
		t.Fatalf("failed reading real linter template: %v", err)
	}
	srv := newTestServer(t, website.Config{
		APIURL: "api.test.osv.dev",
		StaticFS: fstest.MapFS{
			"base.html":   &fstest.MapFile{Data: []byte(`<html>{{ block "content" . }}{{ end }}</html>`)},
			"404.html":    &fstest.MapFile{Data: []byte(`{{ define "content" }}404{{ end }}`)},
			"linter.html": &fstest.MapFile{Data: tmplBytes},
		},
	})
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/linter", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `data-api-url="api.test.osv.dev"`) {
		t.Errorf("GET /linter = %d, body missing data-api-url:\n%s", rec.Code, rec.Body.String())
	}

	// RedirectLinterToTest redirects non-osv.dev hosts without initializing or querying LinterStore.
	prodStore := &richLinterStore{fetchCounts: make(map[string]int)}
	prodSrv := newTestServer(t, website.Config{RedirectLinterToTest: true, Stores: website.Stores{Linter: prodStore}})
	prodReq := httptest.NewRequest(http.MethodGet, "/linter-findings/query?source=ghsa", nil)
	prodReq.Host = "osv-website-xyz.a.run.app"
	prodRec := httptest.NewRecorder()
	prodSrv.ServeHTTP(prodRec, prodReq)
	if prodRec.Code != http.StatusFound || prodStore.listInfosCount != 0 {
		t.Errorf("prod redirect = %d (listInfosCount=%d), want 302 and 0 store calls", prodRec.Code, prodStore.listInfosCount)
	}
}

func TestLinterIndex_CachingAndFallbacks(t *testing.T) {
	t.Parallel()
	srv, store, repoStore := setupLinterTestServer(t, 10*time.Millisecond)

	if got := queryLinter(t, srv, ""); got.Total != 4 {
		t.Fatalf("expected 4 initial issues, got %d", got.Total)
	}

	// Unchanged generations after TTL expiry re-check ListSourceInfos without re-fetching payloads.
	time.Sleep(15 * time.Millisecond)
	_ = queryLinter(t, srv, "")
	store.mu.Lock()
	if store.listInfosCount != 2 || store.fetchCounts["cve-osv"] != 1 {
		t.Fatalf("expected listInfosCount=2 and fetchCounts[cve-osv]=1, got %d and %v", store.listInfosCount, store.fetchCounts)
	}
	store.infos[1].Generation = 201
	store.payloads["cve-osv"] = `{
		"tmp/tmp/CVE-2026-0001.json": [{"Code": "REC:001", "Message": "Invalid Affected"}],
		"tmp/tmp/CVE-2026-0002.json": [{"Code": "SCH:001", "Message": "New schema error"}]
	}`
	store.mu.Unlock()

	time.Sleep(15 * time.Millisecond)
	if updated := queryLinter(t, srv, ""); updated.Total != 5 || store.fetchCounts["chainguard"] != 1 || store.fetchCounts["cve-osv"] != 2 {
		t.Fatalf("expected 5 issues and selective fetch after bump, got total=%d counts=%v", updated.Total, store.fetchCounts)
	}

	// Degraded fallbacks: ListSourceInfos outage, GetFindings error, corrupt JSON, and SourceRepository error.
	store.mu.Lock()
	store.listErr = errors.New("GCS list outage")
	store.mu.Unlock()
	time.Sleep(15 * time.Millisecond)
	if stale := queryLinter(t, srv, ""); stale.Total != 5 {
		t.Fatalf("expected stale 5 issues on ListSourceInfos error, got %d", stale.Total)
	}

	store.mu.Lock()
	store.listErr = nil
	store.infos[0].Generation = 101
	store.fetchErrs["chainguard"] = errors.New("GCS 503")
	store.infos[2].Generation = 301
	store.payloads["ghsa"] = `{corrupt-json`
	store.mu.Unlock()
	repoStore.iterErr = errors.New("datastore iterator timeout")

	time.Sleep(15 * time.Millisecond)
	degraded := queryLinter(t, srv, "")
	if degraded.Total != 5 || !slices.ContainsFunc(degraded.Facets.Sources, func(s website.LinterSourceFacet) bool { return s.Name == "alpine" }) {
		t.Fatalf("expected cached findings and sources preserved on partial errors, got total=%d facets=%+v", degraded.Total, degraded.Facets.Sources)
	}

	// Cold-start failure with no prior snapshot returns 500.
	coldFailSrv := newTestServer(t, website.Config{Stores: website.Stores{Linter: &richLinterStore{listErr: errors.New("down")}}})
	coldRec := httptest.NewRecorder()
	coldFailSrv.ServeHTTP(coldRec, httptest.NewRequest(http.MethodGet, "/linter-findings/query", nil))
	if coldRec.Code != http.StatusInternalServerError {
		t.Errorf("cold-start failure status = %d, want 500", coldRec.Code)
	}
}

func TestLinterIndex_AsyncTimestampEnrichment(t *testing.T) {
	t.Parallel()
	gcsUpdated := time.Date(2026, 4, 1, 10, 0, 0, 0, time.UTC)
	enrichedTime := time.Date(2026, 4, 2, 15, 30, 0, 0, time.UTC)
	gate := make(chan struct{})

	srv := newTestServer(t, website.Config{
		Stores: website.Stores{
			Linter: &richLinterStore{
				infos:    []models.LinterSourceInfo{{Source: "ghsa", Updated: gcsUpdated, Generation: 10}},
				payloads: map[string]string{"ghsa": `{"tmp/GHSA-slow.json": [{"Code": "SCH:001", "Message": "bad json"}]}`},
			},
			ImportFindings: richImportFindingsStore{
				gate:     gate,
				findings: map[string]int64{"GHSA-slow": enrichedTime.Unix()},
			},
		},
	})

	if cold := queryLinter(t, srv, ""); cold.Issues[0].LastAttempt != gcsUpdated.Format(time.RFC3339) {
		t.Fatalf("expected cold-start GCS fallback %s, got %s", gcsUpdated.Format(time.RFC3339), cold.Issues[0].LastAttempt)
	}

	close(gate)
	for range 100 {
		if enriched := queryLinter(t, srv, ""); enriched.TimestampsReady && enriched.Issues[0].LastAttempt == enrichedTime.Format(time.RFC3339) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for background ImportFindings timestamp enrichment")
}

func TestLinterQuery_MissingFirstSeenSortsLast(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Truncate(time.Second)
	linterStore := &richLinterStore{
		infos: []models.LinterSourceInfo{{Source: "ghsa", Generation: 1}},
		payloads: map[string]string{
			"ghsa": `{
				"tmp/tmp/GHSA-new.json": [{"Code": "SCH:001", "Message": "a"}],
				"tmp/tmp/GHSA-old.json": [{"Code": "SCH:001", "Message": "b"}],
				"tmp/tmp/GHSA-zero.json": [{"Code": "SCH:001", "Message": "c"}]
			}`,
		},
	}
	srv := newTestServer(t, website.Config{
		Stores: website.Stores{
			Linter: linterStore,
			ImportFindings: richImportFindingsStore{
				findings: map[string]int64{
					"GHSA-new":  now.Unix(),
					"GHSA-old":  now.Unix(),
					"GHSA-zero": now.Unix(),
				},
				firstSeen: map[string]int64{
					"GHSA-new": now.Add(-1 * time.Hour).Unix(),
					"GHSA-old": now.Add(-48 * time.Hour).Unix(),
					// GHSA-zero intentionally has zero FirstSeen
				},
			},
		},
	})

	desc := queryLinter(t, srv, "sort=first_seen&order=desc")
	if got := []string{desc.Issues[0].BugID, desc.Issues[1].BugID, desc.Issues[2].BugID}; !slices.Equal(got, []string{"GHSA-new", "GHSA-old", "GHSA-zero"}) {
		t.Errorf("sort=first_seen desc = %v, want [GHSA-new GHSA-old GHSA-zero]", got)
	}

	asc := queryLinter(t, srv, "sort=first_seen&order=asc")
	if got := []string{asc.Issues[0].BugID, asc.Issues[1].BugID, asc.Issues[2].BugID}; !slices.Equal(got, []string{"GHSA-old", "GHSA-new", "GHSA-zero"}) {
		t.Errorf("sort=first_seen asc = %v, want [GHSA-old GHSA-new GHSA-zero]", got)
	}
}
