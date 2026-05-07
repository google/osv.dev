package worker

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	gitterpb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline/registry"
	"github.com/ossf/osv-schema/bindings/go/osvconstants"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"k8s.io/apimachinery/pkg/util/yaml"
)

type mockRelationsStore struct{}

func (m mockRelationsStore) GetAliases(_ context.Context, _ string) (*models.GetAliasResult, error) {
	return nil, models.ErrNotFound
}

func (m mockRelationsStore) GetRelated(_ context.Context, _ string) (*models.GetRelatedResult, error) {
	return nil, models.ErrNotFound
}

func (m mockRelationsStore) GetUpstream(_ context.Context, _ string) (*models.GetUpstreamResult, error) {
	return nil, models.ErrNotFound
}

type mockSourceRepoStore struct {
	models.SourceRepositoryStore

	repo *models.SourceRepository
}

func (m mockSourceRepoStore) Get(_ context.Context, _ string) (*models.SourceRepository, error) {
	return m.repo, nil
}

type mockVulnerabilityStore struct {
	models.VulnerabilityStore

	existing *osvschema.Vulnerability
	written  *models.WriteRequest
}

func (m *mockVulnerabilityStore) Get(_ context.Context, _ string) (*osvschema.Vulnerability, error) {
	if m.existing == nil {
		return nil, models.ErrNotFound
	}

	return m.existing, nil
}

func (m *mockVulnerabilityStore) Write(_ context.Context, req models.WriteRequest) error {
	m.written = &req
	return nil
}

func TestPipeline_EndToEnd_PortedFromPython(t *testing.T) {
	ctx := context.Background()

	// 1. Mock gitter response to simulate git analysis
	mockResp := &gitterpb.AffectedCommitsResponse{
		Commits: []*gitterpb.Commit{
			{Hash: []byte("4c155795426727ea05575bd5904321def23c03f4")},
			{Hash: []byte("b1c95a196f22d06fcf80df8c6691cd113d8fefff")},
			{Hash: []byte("eefe8ec3f1f90d0e684890e810f3f21e8500a4cd")},
			{Hash: []byte("febfac1940086bc1f6d3dc33fda0a1d1ba336209")},
			{Hash: []byte("ff8cc32ba60ad9cbb3b23f0a82aad96ebe9ff76b")},
		},
		Tags: []*gitterpb.Ref{
			{Label: "branch_1_cherrypick_regress"},
			{Label: "v0.1.1"},
		},
		CherryPickedEvents: []*gitterpb.Event{
			{EventType: gitterpb.EventType_INTRODUCED, Hash: "febfac1940086bc1f6d3dc33fda0a1d1ba336209"},
			{EventType: gitterpb.EventType_FIXED, Hash: "b9b3fd4732695b83c3068b7b6a14bb372ec31f98"},
		},
	}
	mockRespBytes, _ := proto.Marshal(mockResp)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(mockRespBytes)
	}))
	defer server.Close()

	mockVulnStore := &mockVulnerabilityStore{
		existing: &osvschema.Vulnerability{
			Id:        "OSV-123",
			Published: timestamppb.New(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
			Modified:  timestamppb.New(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
	}

	engine := &Engine{
		Pipeline:     registry.List,
		GitterHost:   server.URL,
		GitterClient: server.Client(),
		Stores: Stores{
			SourceRepo: mockSourceRepoStore{
				repo: &models.SourceRepository{
					Name: "source",
					GitAnalysis: &models.GitAnalysisConfig{
						IgnoreGit: false,
					},
				},
			},
			Vulnerability: mockVulnStore,
			Relations:     mockRelationsStore{},
		},
	}

	// 2. Load input YAML (OSV-123.yaml)
	inputPath := filepath.Join("testdata", "OSV-123.yaml")
	inputBytes, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("Failed to read input file: %v", err)
	}

	var vuln osvschema.Vulnerability
	jsonBytes, err := yaml.ToJSON(inputBytes)
	if err != nil {
		t.Fatalf("Failed to convert YAML to JSON: %v", err)
	}
	if err := protojson.Unmarshal(jsonBytes, &vuln); err != nil {
		t.Fatalf("Failed to unmarshal protojson: %v", err)
	}

	task := Task{
		Type:         TaskUpdate,
		SourceID:     "source",
		PathInSource: "OSV-123.yaml",
		Vuln:         &vuln,
	}

	// 3. Run handleUpdate
	if err := engine.handleUpdate(ctx, task); err != nil {
		t.Fatalf("handleUpdate failed: %v", err)
	}

	// 4. Verify results from mock store
	if mockVulnStore.written == nil {
		t.Fatalf("Expected vulnerability to be written, but it wasn't")
	}

	enriched := mockVulnStore.written.Enriched

	expectedVuln := &osvschema.Vulnerability{
		Id:            "OSV-123",
		Summary:       "A vulnerability",
		Details:       "Blah blah blah\nBlah\n", //nolint:dupword
		SchemaVersion: osvconstants.SchemaVersion,
		Published:     timestamppb.New(time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)),
		Severity: []*osvschema.Severity{
			{
				Type:  osvschema.Severity_CVSS_V3,
				Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
			},
		},
		Credits: []*osvschema.Credit{
			{
				Name: "Foo bar",
				Contact: []string{
					"mailto:foo@bar.com",
				},
			},
		},
		References: []*osvschema.Reference{
			{
				Type: osvschema.Reference_WEB,
				Url:  "https://ref.com/ref",
			},
		},
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "Go",
					Name:      "blah.com/package",
					Purl:      "pkg:golang/blah.com/package",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
						Repo: "https://osv-test/repo/url",
						Events: []*osvschema.Event{
							{Introduced: "eefe8ec3f1f90d0e684890e810f3f21e8500a4cd"},
							{Fixed: "8d8242f545e9cec3e6d0d2e3f5bde8be1c659735"},
							{Introduced: "febfac1940086bc1f6d3dc33fda0a1d1ba336209"},
							{Fixed: "b9b3fd4732695b83c3068b7b6a14bb372ec31f98"},
						},
					},
				},
				Versions: []string{"branch-v0.1.1", "branch_1_cherrypick_regress", "v0.1.1"},
			},
		},
	}

	var errConstruct error
	expectedVuln.DatabaseSpecific, errConstruct = structpb.NewStruct(map[string]any{"specific": 1337.0})
	if errConstruct != nil {
		t.Fatalf("Failed to construct expected database_specific: %v", errConstruct)
	}

	opts := []cmp.Option{
		protocmp.Transform(),
		protocmp.IgnoreFields(&osvschema.Vulnerability{}, "modified"),
	}

	if diff := cmp.Diff(expectedVuln, enriched, opts...); diff != "" {
		t.Errorf("Vulnerability mismatch (-want +got):\n%s", diff)
	}

	// Verify that the modified date was pushed forward
	existingModified := time.Date(2021, 1, 1, 0, 0, 0, 0, time.UTC)
	if !enriched.GetModified().AsTime().After(existingModified) {
		t.Errorf("Expected modified date to be after %v, got %v", existingModified, enriched.GetModified().AsTime())
	}
}
