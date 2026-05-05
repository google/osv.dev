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
