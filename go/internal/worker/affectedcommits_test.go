package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
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
