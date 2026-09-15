package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

func TestPopulateAffectedCommitsAndTags(t *testing.T) {
	// Mock gitter response
	mockResp := &gitterpb.AffectedCommitsResponse{
		Commits: []*gitterpb.Commit{
			{Hash: []byte("a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4")},
			{Hash: []byte("b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5")},
		},
		Tags: []*gitterpb.Ref{
			{Label: "v1.0.0", Hash: []byte("a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4")},
		},
		CherryPickedEvents: []*gitterpb.Event{
			{EventType: gitterpb.EventType_INTRODUCED, Hash: "c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f6"},
			{EventType: gitterpb.EventType_LIMIT, Hash: "e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"},
		},
	}
	mockRespBytes, _ := proto.Marshal(mockResp)

	// Create mock server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(mockRespBytes); err != nil {
			t.Errorf("Failed to write mock response: %v", err)
		}
	}))
	defer server.Close()

	e := &Engine{
		GitterHost:   server.URL,
		GitterClient: server.Client(),
	}
	vuln := &osvschema.Vulnerability{
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "https://github.com/example/repo",
						Events: []*osvschema.Event{
							{Introduced: "d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"},
						},
					},
				},
			},
		},
	}
	sourceRepo := &models.SourceRepository{
		GitAnalysis: &models.GitAnalysisConfig{
			IgnoreGit: false,
		},
	}

	affectedCommitsRes, err := e.populateAffectedCommitsAndTags(context.Background(), vuln, sourceRepo)
	if err != nil {
		t.Fatalf("populateAffectedCommitsAndTags failed: %v", err)
	}

	// Verify commits
	if len(affectedCommitsRes.Commits) != 2 {
		t.Errorf("expected 2 commits, got %d", len(affectedCommitsRes.Commits))
	}

	// Verify tags
	affected := vuln.GetAffected()[0]
	if len(affected.GetVersions()) != 1 || affected.GetVersions()[0] != "v1.0.0" {
		t.Errorf("expected version v1.0.0, got %v", affected.GetVersions())
	}

	// Verify cherry-picked events
	aRange := affected.GetRanges()[0]
	if len(aRange.GetEvents()) != 3 {
		t.Errorf("expected 3 events, got %d", len(aRange.GetEvents()))
	}
}

func TestPopulateAffectedCommitsAndTagsUnexpectedStatus(t *testing.T) {
	const (
		repoURL = "https://github.com/example/repo"
		refID   = "OSV-2024-TEST"
		// Matches gitter's affectedCommitsHandler: http.Error(w, fmt.Sprintf("Error getting repo: %v", err), statusCode)
		body = "Error getting repo: command git failed: exit status 128, output: fatal: remote hung up unexpectedly"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/affected-commits" {
			t.Errorf("unexpected path %s", r.URL.Path)
		}
		http.Error(w, body, http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	e := &Engine{
		GitterHost:   server.URL,
		GitterClient: server.Client(),
	}
	vuln := &osvschema.Vulnerability{
		Id: refID,
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: repoURL,
						Events: []*osvschema.Event{
							{Introduced: "d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"},
							{Fixed: "e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"},
						},
					},
				},
			},
		},
	}
	sourceRepo := &models.SourceRepository{
		GitAnalysis: &models.GitAnalysisConfig{
			IgnoreGit:           false,
			ConsiderAllBranches: true,
			DetectCherrypicks:   true,
		},
	}

	_, err := e.populateAffectedCommitsAndTags(context.Background(), vuln, sourceRepo)
	if err == nil {
		t.Fatal("expected error from gitter 500 response")
	}
	got := err.Error()
	t.Logf("gitter 500 error: %v", err)
	for _, want := range []string{
		"gitter responded with 500 Internal Server Error",
		`repo "https://github.com/example/repo"`,
		`ref_id "OSV-2024-TEST"`,
		"request_url " + server.URL + "/affected-commits",
		"events [introduced=d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678, fixed=e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890]",
		"flags consider_all_branches=true cherrypicks_introduced=true cherrypicks_fixed=true cherrypicks_limit=true",
		body,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q does not include %q", got, want)
		}
	}
}

func TestFetchAffectedCommitsUnexpectedStatus(t *testing.T) {
	const (
		repoURL = "https://github.com/example/repo"
		refID   = "OSV-2024-TEST"
		body    = "Error getting repo: git fetch failed: remote hung up"
	)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	aRange := &osvschema.Range{
		Type: osvschema.Range_GIT,
		Repo: repoURL,
		Events: []*osvschema.Event{
			{Introduced: "d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"},
		},
	}
	flags := models.RepoAllowListFlags{ConsiderAllBranches: true}

	_, err := fetchAffectedCommits(context.Background(), server.Client(), server.URL, aRange, refID, flags)
	if err == nil {
		t.Fatal("expected error from gitter 500 response")
	}
	t.Logf("gitter 500 error: %v", err)
	got := err.Error()
	for _, want := range []string{
		"gitter responded with 500 Internal Server Error",
		`repo "https://github.com/example/repo"`,
		`ref_id "OSV-2024-TEST"`,
		"request_url " + server.URL + "/affected-commits",
		"events [introduced=d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678]",
		"flags consider_all_branches=true cherrypicks_introduced=false cherrypicks_fixed=false cherrypicks_limit=false",
		body,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q does not include %q", got, want)
		}
	}
}

func TestFetchAffectedCommitsUnexpectedStatusTruncatesBody(t *testing.T) {
	body := strings.Repeat("x", 2048)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := w.Write([]byte(body)); err != nil {
			t.Errorf("Failed to write mock response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	aRange := &osvschema.Range{
		Type: osvschema.Range_GIT,
		Repo: "https://github.com/example/repo",
		Events: []*osvschema.Event{
			{Introduced: "d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"},
		},
	}

	_, err := fetchAffectedCommits(context.Background(), server.Client(), server.URL, aRange, "OSV-2024-TEST", models.RepoAllowListFlags{})
	if err == nil {
		t.Fatal("expected error from gitter 500 response")
	}
	got := err.Error()
	wantBody := strings.Repeat("x", 1024) + "...(truncated)"
	if !strings.HasSuffix(got, ": "+wantBody) {
		t.Fatalf("error %q does not end with truncated body", got)
	}
}

func TestFetchAffectedCommitsUnexpectedStatusRedactsUserinfo(t *testing.T) {
	const secret = "ghp_supersecret"
	body := "Error getting repo: fatal: could not read Username for 'https://x-access-token:" + secret + "@github.com/private/repo.git'"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	aRange := &osvschema.Range{
		Type: osvschema.Range_GIT,
		Repo: "https://x-access-token:" + secret + "@github.com/private/repo.git",
		Events: []*osvschema.Event{
			{Introduced: "d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f678"},
		},
	}

	_, err := fetchAffectedCommits(context.Background(), server.Client(), server.URL, aRange, "OSV-2024-TEST", models.RepoAllowListFlags{})
	if err == nil {
		t.Fatal("expected error from gitter 500 response")
	}
	got := err.Error()
	if strings.Contains(got, secret) {
		t.Fatalf("error leaked credential: %q", got)
	}
	for _, want := range []string{
		"gitter responded with 500 Internal Server Error",
		`repo "https://REDACTED@github.com/private/repo.git"`,
		"https://REDACTED@github.com/private/repo.git",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q does not include %q", got, want)
		}
	}
}

func TestUnexpectedGitterStatusErrorNilResponse(t *testing.T) {
	err := unexpectedGitterStatusError(nil, &osvschema.Range{Repo: "https://github.com/example/repo"}, "OSV-2024-TEST", models.RepoAllowListFlags{})
	if err == nil {
		t.Fatal("expected error")
	}
	got := err.Error()
	for _, want := range []string{
		"gitter responded with unknown status",
		`repo "https://github.com/example/repo"`,
		`ref_id "OSV-2024-TEST"`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("error %q does not include %q", got, want)
		}
	}
}

type mockRepoAllowListStore struct {
	flags map[string]models.RepoAllowListFlags
}

func (m *mockRepoAllowListStore) GetFlags(_ context.Context, repoURL string) (models.RepoAllowListFlags, error) {
	if m.flags == nil {
		return models.RepoAllowListFlags{}, nil
	}

	return m.flags[repoURL], nil
}

func TestGetGitAnalysisFlags(t *testing.T) {
	ctx := context.Background()
	mockStore := &mockRepoAllowListStore{
		flags: map[string]models.RepoAllowListFlags{
			"https://github.com/test-org/store-enabled-repo": {
				ConsiderAllBranches: true,
				CherrypicksFixed:    true,
			},
			"https://github.com/test-org/store-all-false-repo": {},
		},
	}

	engineWithAllowlist := &Engine{
		Stores: Stores{
			RepoAllowList: mockStore,
		},
	}
	engineWithoutAllowlist := &Engine{}

	sourceRepoAllFalse := &models.SourceRepository{
		GitAnalysis: &models.GitAnalysisConfig{ConsiderAllBranches: false, DetectCherrypicks: false},
	}
	sourceRepoAllTrue := &models.SourceRepository{
		GitAnalysis: &models.GitAnalysisConfig{ConsiderAllBranches: true, DetectCherrypicks: true},
	}

	tests := []struct {
		name       string
		engine     *Engine
		repo       string
		sourceRepo *models.SourceRepository
		wantFlags  models.RepoAllowListFlags
	}{
		{
			name:       "Source repo true, store unlisted (all false) -> returns source repo flags",
			engine:     engineWithAllowlist,
			repo:       "https://github.com/unlisted/repo",
			sourceRepo: sourceRepoAllTrue,
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches:   true,
				CherrypicksIntroduced: true,
				CherrypicksFixed:      true,
				CherrypicksLimit:      true,
			},
		},
		{
			name:       "Source repo false, store unlisted (all false) -> returns all false",
			engine:     engineWithAllowlist,
			repo:       "https://github.com/unlisted/repo",
			sourceRepo: sourceRepoAllFalse,
			wantFlags:  models.RepoAllowListFlags{},
		},
		{
			name:       "Source repo false, store repo explicitly all false -> returns all false",
			engine:     engineWithAllowlist,
			repo:       "https://github.com/test-org/store-all-false-repo",
			sourceRepo: sourceRepoAllFalse,
			wantFlags:  models.RepoAllowListFlags{},
		},
		{
			name:       "Source repo false, store repo has flags true -> returns store flags",
			engine:     engineWithAllowlist,
			repo:       "https://github.com/test-org/store-enabled-repo",
			sourceRepo: sourceRepoAllFalse,
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches: true,
				CherrypicksFixed:    true,
			},
		},
		{
			name:   "Source repo true, store repo has different flags true -> returns merged flags",
			engine: engineWithAllowlist,
			repo:   "https://github.com/test-org/store-enabled-repo",
			sourceRepo: &models.SourceRepository{
				GitAnalysis: &models.GitAnalysisConfig{ConsiderAllBranches: false, DetectCherrypicks: true},
			},
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches:   true,
				CherrypicksIntroduced: true,
				CherrypicksFixed:      true,
				CherrypicksLimit:      true,
			},
		},
		{
			name:       "Nil source repo, store repo has flags true -> returns store flags",
			engine:     engineWithAllowlist,
			repo:       "https://github.com/test-org/store-enabled-repo",
			sourceRepo: nil,
			wantFlags: models.RepoAllowListFlags{
				ConsiderAllBranches: true,
				CherrypicksFixed:    true,
			},
		},
		{
			name:       "Nil source repo, store unlisted -> returns all false",
			engine:     engineWithAllowlist,
			repo:       "https://github.com/unlisted/repo",
			sourceRepo: nil,
			wantFlags:  models.RepoAllowListFlags{},
		},
		{
			name:       "Nil allowlist store, source repo false -> returns all false",
			engine:     engineWithoutAllowlist,
			repo:       "https://github.com/test-org/store-enabled-repo",
			sourceRepo: sourceRepoAllFalse,
			wantFlags:  models.RepoAllowListFlags{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gitAnalysis *models.GitAnalysisConfig
			if tt.sourceRepo != nil {
				gitAnalysis = tt.sourceRepo.GitAnalysis
			}
			got := tt.engine.getGitAnalysisFlags(ctx, gitAnalysis, tt.repo)
			if got != tt.wantFlags {
				t.Errorf("getGitAnalysisFlags(%q) = %+v, want %+v", tt.repo, got, tt.wantFlags)
			}
		})
	}
}
