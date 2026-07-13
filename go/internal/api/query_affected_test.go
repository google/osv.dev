package api

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"strings"
	"sync"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"

	pb "osv.dev/bindings/go/api"
)

type mockQueryVulnStore struct {
	models.UnimplementedVulnerabilityStore

	// Mock behavior trackers
	matchCommits  func(ctx context.Context, commit []byte, cursor string) iter.Seq2[models.MatchResult, error]
	matchPackages func(ctx context.Context, ecosystem, name, version, cursor string) iter.Seq2[models.MatchResult, error]
	get           func(ctx context.Context, id string) (*osvschema.Vulnerability, error)
	getModified   func(ctx context.Context, id string) (time.Time, error)
}

func (m *mockQueryVulnStore) MatchCommits(ctx context.Context, commit []byte, cursor string) iter.Seq2[models.MatchResult, error] {
	if m.matchCommits != nil {
		return m.matchCommits(ctx, commit, cursor)
	}

	return func(_ func(models.MatchResult, error) bool) {}
}

func (m *mockQueryVulnStore) MatchPackages(ctx context.Context, ecosystem, name, version, cursor string) iter.Seq2[models.MatchResult, error] {
	if m.matchPackages != nil {
		return m.matchPackages(ctx, ecosystem, name, version, cursor)
	}

	return func(_ func(models.MatchResult, error) bool) {}
}

func (m *mockQueryVulnStore) GetFull(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	if m.get != nil {
		return m.get(ctx, id)
	}

	return nil, models.ErrNotFound
}

func (m *mockQueryVulnStore) GetModified(ctx context.Context, id string) (time.Time, error) {
	if m.getModified != nil {
		return m.getModified(ctx, id)
	}

	return time.Time{}, models.ErrNotFound
}

func (m *mockQueryVulnStore) MatchPackagesBatch(ctx context.Context, queries []models.PackageQuery) ([]iter.Seq2[models.MatchResult, error], error) {
	results := make([]iter.Seq2[models.MatchResult, error], len(queries))
	for i, q := range queries {
		results[i] = m.MatchPackages(ctx, q.Ecosystem, q.Name, q.Version, q.Cursor)
	}

	return results, nil
}

func (m *mockQueryVulnStore) MatchCommitsBatch(ctx context.Context, queries []models.CommitQuery) ([]iter.Seq2[models.MatchResult, error], error) {
	results := make([]iter.Seq2[models.MatchResult, error], len(queries))
	for i, q := range queries {
		results[i] = m.MatchCommits(ctx, q.Commit, q.Cursor)
	}

	return results, nil
}

type mockPublishResult struct {
	id  string
	err error
}

func (r *mockPublishResult) Get(_ context.Context) (string, error) {
	return r.id, r.err
}

type mockPublisher struct {
	messages []*pubsub.Message
	mu       sync.Mutex
	err      error
}

func (p *mockPublisher) Publish(_ context.Context, msg *pubsub.Message) clients.PublishResult {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.messages = append(p.messages, msg)

	return &mockPublishResult{id: "mock-msg-id", err: p.err}
}

func TestQueryAffected_Validation(t *testing.T) {
	ctx := context.Background()
	s := &server{
		vulnStore: &mockQueryVulnStore{},
	}

	tests := []struct {
		name        string
		params      *pb.QueryAffectedParameters
		wantErrCode codes.Code
		wantErrMsg  string
	}{
		{
			name:        "No params or query",
			params:      nil,
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "no query provided",
		},
		{
			name:        "Empty Query",
			params:      &pb.QueryAffectedParameters{Query: &pb.Query{}},
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "invalid query",
		},
		{
			name: "Redundant ecosystem inside a PURL query",
			params: &pb.QueryAffectedParameters{
				Query: &pb.Query{
					Package: &osvschema.Package{
						Ecosystem: "PyPI",
						Purl:      "pkg:pypi/mlflow@0.4.0",
					},
				},
			},
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "ecosystem specified in a PURL query",
		},
		{
			name: "Redundant version inside a PURL query",
			params: &pb.QueryAffectedParameters{
				Query: &pb.Query{
					Param: &pb.Query_Version{
						Version: "0.4.0",
					},
					Package: &osvschema.Package{
						Purl: "pkg:pypi/mlflow@0.4.0",
					},
				},
			},
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "version specified in params and PURL query",
		},
		{
			name: "Redundant name inside a PURL query",
			params: &pb.QueryAffectedParameters{
				Query: &pb.Query{
					Package: &osvschema.Package{
						Name: "mlflow",
						Purl: "pkg:pypi/mlflow@0.4.0",
					},
				},
			},
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "name specified in a PURL query",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.QueryAffected(ctx, tt.params)
			if err == nil {
				t.Fatalf("Expected validation error, got nil")
			}
			st, ok := status.FromError(err)
			if !ok {
				t.Fatalf("Expected gRPC status error, got %v", err)
			}
			if st.Code() != tt.wantErrCode {
				t.Errorf("Error code = %v, want %v", st.Code(), tt.wantErrCode)
			}
			if !strings.Contains(st.Message(), tt.wantErrMsg) {
				t.Errorf("Error message = %q, want to contain %q", st.Message(), tt.wantErrMsg)
			}
		})
	}
}

func TestQueryAffected_CommitMatches(t *testing.T) {
	ctx := context.Background()
	testVuln := &osvschema.Vulnerability{Id: "OSV-2023-890"}

	store := &mockQueryVulnStore{
		matchCommits: func(_ context.Context, _ []byte, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				yield(models.MatchResult{
					IsMatch: true,
					ID:      "OSV-2023-890",
					Cursor:  func() string { return "test-cursor" },
				}, nil)
			}
		},
		get: func(_ context.Context, id string) (*osvschema.Vulnerability, error) {
			if id == "OSV-2023-890" {
				return testVuln, nil
			}

			return nil, models.ErrNotFound
		},
	}

	s := &server{
		vulnStore:   store,
		verboseLogs: true,
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param: &pb.Query_Commit{
				Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321",
			},
		},
	}

	got, err := s.QueryAffected(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffected() unexpected error: %v", err)
	}

	want := &pb.VulnerabilityList{
		Vulns: []*osvschema.Vulnerability{testVuln},
	}

	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("QueryAffected() mismatch (-want +got):\n%s", diff)
	}
}

func TestQueryAffected_TimeoutSafety(t *testing.T) {
	ctx := context.Background()
	testVuln := &osvschema.Vulnerability{Id: "TEST-VULN"}

	store := &mockQueryVulnStore{
		matchPackages: func(ctx context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				// Emulate a matching process that takes too long
				if !yield(models.MatchResult{
					IsMatch: true,
					ID:      "TEST-VULN",
					Cursor:  func() string { return "mid-cursor" },
				}, nil) {
					return
				}
				select {
				case <-time.After(150 * time.Millisecond):
					yield(models.MatchResult{
						IsMatch: true,
						ID:      "TEST-VULN-2",
						Cursor:  func() string { return "end-cursor" },
					}, nil)
				case <-ctx.Done():
					yield(models.MatchResult{
						IsMatch: false,
					}, ctx.Err())
				}
			}
		},
		get: func(_ context.Context, _ string) (*osvschema.Vulnerability, error) {
			return testVuln, nil
		},
	}

	s := &server{
		vulnStore:          store,
		singleQueryTimeout: 50 * time.Millisecond, // Configure short matcher timeout
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param: &pb.Query_Version{
				Version: "1.0.0",
			},
			Package: &osvschema.Package{
				Name:      "test-pkg",
				Ecosystem: "npm",
			},
		},
	}

	got, err := s.QueryAffected(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffected() unexpected error: %v", err)
	}

	// Should return only the first vuln matched before timeout and provide the correct cursor!
	if len(got.GetVulns()) != 1 || got.GetVulns()[0].GetId() != "TEST-VULN" {
		t.Errorf("Expected exactly 1 vulnerability, got %v", got.GetVulns())
	}

	if got.GetNextPageToken() != "mid-cursor" {
		t.Errorf("Expected page token 'mid-cursor', got %q", got.GetNextPageToken())
	}
}

func TestQueryAffected_SizeLimitSafety(t *testing.T) {
	ctx := context.Background()
	testVuln := &osvschema.Vulnerability{Id: "VULN-1", Summary: "Exceeds size limit"}

	store := &mockQueryVulnStore{
		matchPackages: func(ctx context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				// 1. Yield the first vulnerability
				if !yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-1",
					Cursor:  func() string { return "cursor-1" },
				}, nil) {
					return
				}

				// 2. Block and wait for the size-limit cancellation to propagate!
				select {
				case <-ctx.Done():
					// Yield the cancellation error explicitly!
					yield(models.MatchResult{IsMatch: false}, ctx.Err())
					return
				case <-time.After(200 * time.Millisecond):
					// Failure fallback: if cancellation failed to propagate,
					// we yield a second item which will fail the assertion.
					yield(models.MatchResult{
						IsMatch: true,
						ID:      "VULN-2",
						Cursor:  func() string { return "cursor-2" },
					}, nil)
				}
			}
		},
		get: func(_ context.Context, _ string) (*osvschema.Vulnerability, error) {
			return testVuln, nil
		},
	}

	s := &server{
		vulnStore:         store,
		responseSizeLimit: 10, // Tiny limit to trigger cancellation after VULN-1
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param:   &pb.Query_Version{Version: "1.0.0"},
			Package: &osvschema.Package{Name: "test-pkg", Ecosystem: "npm"},
		},
	}

	got, err := s.QueryAffected(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffected() unexpected error: %v", err)
	}

	// We should receive ONLY VULN-1 because the matcher exited on size limit cancellation
	if len(got.GetVulns()) != 1 || got.GetVulns()[0].GetId() != "VULN-1" {
		t.Errorf("Expected exactly 1 vulnerability, got %v", got.GetVulns())
	}

	// The page token must remain "cursor-1"
	if got.GetNextPageToken() != "cursor-1" {
		t.Errorf("Expected next page token 'cursor-1', got %q", got.GetNextPageToken())
	}
}

func TestQueryAffectedBatch_Success(t *testing.T) {
	ctx := context.Background()
	pkgModTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	commitModTime := time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC)

	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-PKG",
					Cursor:  func() string { return "pkg-cursor-1" },
				}, nil)
			}
		},
		matchCommits: func(_ context.Context, _ []byte, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-COMMIT",
					Cursor:  func() string { return "commit-cursor-1" },
				}, nil)
			}
		},
		getModified: func(_ context.Context, id string) (time.Time, error) {
			if id == "VULN-PKG" {
				return pkgModTime, nil
			}
			if id == "VULN-COMMIT" {
				return commitModTime, nil
			}

			return time.Time{}, models.ErrNotFound
		},
	}

	s := &server{
		vulnStore: store,
	}

	params := &pb.QueryAffectedBatchParameters{
		Query: &pb.BatchQuery{
			Queries: []*pb.Query{
				{
					Param:   &pb.Query_Version{Version: "1.0.0"},
					Package: &osvschema.Package{Name: "test-pkg", Ecosystem: "npm"},
				},
				{
					Param: &pb.Query_Commit{Commit: "60e572dbf7b4ded66b488f54773f66aaf6184321"},
				},
				{
					Package: &osvschema.Package{Purl: "pkg:unknown/purl@1.0.0"}, // Unknown PURL
				},
			},
		},
	}

	got, err := s.QueryAffectedBatch(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffectedBatch() unexpected error: %v", err)
	}

	if len(got.GetResults()) != 3 {
		t.Fatalf("Expected exactly 3 results, got %d", len(got.GetResults()))
	}

	// Verify Result 0: Package Query (Minimal details)
	res0 := got.GetResults()[0]
	if len(res0.GetVulns()) != 1 || res0.GetVulns()[0].GetId() != "VULN-PKG" {
		t.Errorf("Result 0 mismatch: expected 'VULN-PKG', got %v", res0.GetVulns())
	}
	if res0.GetVulns()[0].GetModified().AsTime() != pkgModTime {
		t.Errorf("Result 0 modified time mismatch: expected %v, got %v", pkgModTime, res0.GetVulns()[0].GetModified().AsTime())
	}
	if res0.GetNextPageToken() != "" {
		t.Errorf("Result 0 next page token expected empty, got %q", res0.GetNextPageToken())
	}

	// Verify Result 1: Commit Query (Minimal details)
	res1 := got.GetResults()[1]
	if len(res1.GetVulns()) != 1 || res1.GetVulns()[0].GetId() != "VULN-COMMIT" {
		t.Errorf("Result 1 mismatch: expected 'VULN-COMMIT', got %v", res1.GetVulns())
	}
	if res1.GetVulns()[0].GetModified().AsTime() != commitModTime {
		t.Errorf("Result 1 modified time mismatch: expected %v, got %v", commitModTime, res1.GetVulns()[0].GetModified().AsTime())
	}
	if res1.GetNextPageToken() != "" {
		t.Errorf("Result 1 next page token expected empty, got %q", res1.GetNextPageToken())
	}

	// Verify Result 2: Unknown PURL (Empty result)
	res2 := got.GetResults()[2]
	if len(res2.GetVulns()) != 0 {
		t.Errorf("Result 2 expected empty vulnerabilities, got %v", res2.GetVulns())
	}
	if res2.GetNextPageToken() != "" {
		t.Errorf("Result 2 next page token expected empty, got %q", res2.GetNextPageToken())
	}
}

func TestQueryAffectedBatch_SizeLimitSafety(t *testing.T) {
	ctx := context.Background()

	store := &mockQueryVulnStore{
		matchPackages: func(ctx context.Context, _, name, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				switch name {
				case "pkg-1":
					// 1. Yield the first vulnerability
					if !yield(models.MatchResult{
						IsMatch: true,
						ID:      "VULN-1",
						Cursor:  func() string { return "cursor-1" },
					}, nil) {
						return
					}
					// 2. Block and wait for cancellation
					select {
					case <-ctx.Done():
						yield(models.MatchResult{IsMatch: false}, ctx.Err())
						return
					case <-time.After(200 * time.Millisecond):
						yield(models.MatchResult{
							IsMatch: true,
							ID:      "VULN-1-extra",
							Cursor:  func() string { return "cursor-1-extra" },
						}, nil)
					}
				case "pkg-2":
					// 1. Yield the first vulnerability
					if !yield(models.MatchResult{
						IsMatch: true,
						ID:      "VULN-2",
						Cursor:  func() string { return "cursor-2" },
					}, nil) {
						return
					}
					// 2. Block and wait for cancellation
					select {
					case <-ctx.Done():
						yield(models.MatchResult{IsMatch: false}, ctx.Err())
						return
					case <-time.After(200 * time.Millisecond):
						yield(models.MatchResult{
							IsMatch: true,
							ID:      "VULN-2-extra",
							Cursor:  func() string { return "cursor-2-extra" },
						}, nil)
					}
				}
			}
		},
		getModified: func(_ context.Context, _ string) (time.Time, error) {
			return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), nil
		},
	}

	s := &server{
		vulnStore:         store,
		responseSizeLimit: 10, // Tiny limit to trigger cancellation after VULN-1
	}

	params := &pb.QueryAffectedBatchParameters{
		Query: &pb.BatchQuery{
			Queries: []*pb.Query{
				{
					Param:   &pb.Query_Version{Version: "1.0.0"},
					Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
				},
				{
					Param:   &pb.Query_Version{Version: "1.0.0"},
					Package: &osvschema.Package{Name: "pkg-2", Ecosystem: "npm"},
				},
			},
		},
	}

	got, err := s.QueryAffectedBatch(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffectedBatch() unexpected error: %v", err)
	}

	// Result for pkg-1 should only have VULN-1 (and not VULN-1-extra)
	res0 := got.GetResults()[0]
	if len(res0.GetVulns()) != 1 || res0.GetVulns()[0].GetId() != "VULN-1" {
		t.Errorf("Result 0 expected VULN-1, got %v", res0.GetVulns())
	}

	// Result for pkg-2 should only have VULN-2 (and not VULN-2-extra)
	res1 := got.GetResults()[1]
	if len(res1.GetVulns()) != 1 || res1.GetVulns()[0].GetId() != "VULN-2" {
		t.Errorf("Result 1 expected VULN-2, got %v", res1.GetVulns())
	}
}

func TestQueryAffectedBatch_ValidationError(t *testing.T) {
	ctx := context.Background()
	s := &server{
		vulnStore: &mockQueryVulnStore{},
	}

	params := &pb.QueryAffectedBatchParameters{
		Query: &pb.BatchQuery{
			Queries: []*pb.Query{
				{
					Param:   &pb.Query_Version{Version: "1.0.0"},
					Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
				},
				{
					// Invalid query (empty)
					Package: &osvschema.Package{},
				},
			},
		},
	}

	_, err := s.QueryAffectedBatch(ctx, params)
	if err == nil {
		t.Fatalf("QueryAffectedBatch() expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected code InvalidArgument, got %v", st.Code())
	}

	expectedMsg := "error in query at index 1: rpc error: code = InvalidArgument desc = invalid query"
	if !strings.Contains(st.Message(), expectedMsg) {
		t.Errorf("Expected error message to contain %q, got %q", expectedMsg, st.Message())
	}
}

func TestQueryAffected_HydrationError(t *testing.T) {
	ctx := context.Background()
	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-1",
				}, nil)
			}
		},
		get: func(_ context.Context, _ string) (*osvschema.Vulnerability, error) {
			return nil, errors.New("database connection lost")
		},
	}

	s := &server{
		vulnStore: store,
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param:   &pb.Query_Version{Version: "1.0.0"},
			Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
		},
	}

	_, err := s.QueryAffected(ctx, params)
	if err == nil {
		t.Fatalf("QueryAffected() expected error, got nil")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got %v", err)
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected code Internal, got %v", st.Code())
	}

	expectedMsg := "database connection lost"
	if !strings.Contains(st.Message(), expectedMsg) {
		t.Errorf("Expected error message to contain %q, got %q", expectedMsg, st.Message())
	}
}

func TestQueryAffected_HydrationNotFound(t *testing.T) {
	ctx := context.Background()
	testVuln2 := &osvschema.Vulnerability{Id: "VULN-2"}

	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				if !yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-1",
				}, nil) {
					return
				}
				yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-2",
				}, nil)
			}
		},
		get: func(_ context.Context, id string) (*osvschema.Vulnerability, error) {
			if id == "VULN-1" {
				return nil, models.ErrNotFound
			}
			if id == "VULN-2" {
				return testVuln2, nil
			}

			return nil, models.ErrNotFound
		},
	}

	s := &server{
		vulnStore: store,
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param:   &pb.Query_Version{Version: "1.0.0"},
			Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
		},
	}

	got, err := s.QueryAffected(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffected() unexpected error: %v", err)
	}

	// Should skip VULN-1 and return VULN-2 successfully
	if len(got.GetVulns()) != 1 || got.GetVulns()[0].GetId() != "VULN-2" {
		t.Errorf("Expected only VULN-2, got %v", got.GetVulns())
	}
}

func TestQueryAffected_HydrationNotFound_PublishesRecovery(t *testing.T) {
	ctx := context.Background()
	testVuln2 := &osvschema.Vulnerability{Id: "VULN-2"}

	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				if !yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-1",
				}, nil) {
					return
				}
				yield(models.MatchResult{
					IsMatch: true,
					ID:      "VULN-2",
				}, nil)
			}
		},
		get: func(_ context.Context, id string) (*osvschema.Vulnerability, error) {
			if id == "VULN-1" {
				return nil, models.ErrNotFound
			}
			if id == "VULN-2" {
				return testVuln2, nil
			}

			return nil, models.ErrNotFound
		},
	}

	publisher := &mockPublisher{}

	s := &server{
		vulnStore:          store,
		recovererPublisher: publisher,
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param:   &pb.Query_Version{Version: "1.0.0"},
			Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
		},
	}

	got, err := s.QueryAffected(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffected() unexpected error: %v", err)
	}

	// Should skip VULN-1 and return VULN-2 successfully
	if len(got.GetVulns()) != 1 || got.GetVulns()[0].GetId() != "VULN-2" {
		t.Errorf("Expected only VULN-2, got %v", got.GetVulns())
	}

	// Verify that a recovery message was published for VULN-1
	// We need to wait a tiny bit because publishing is done in a goroutine
	time.Sleep(10 * time.Millisecond)

	publisher.mu.Lock()
	defer publisher.mu.Unlock()

	if len(publisher.messages) != 1 {
		t.Fatalf("Expected exactly 1 published message, got %d", len(publisher.messages))
	}

	msg := publisher.messages[0]
	if msg.Attributes["type"] != "gcs_missing" {
		t.Errorf("Expected message type 'gcs_missing', got %q", msg.Attributes["type"])
	}
	if msg.Attributes["id"] != "VULN-1" {
		t.Errorf("Expected message id 'VULN-1', got %q", msg.Attributes["id"])
	}
}

func TestQueryAffected_NilCursorSafety(t *testing.T) {
	ctx := context.Background()

	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(yield func(models.MatchResult, error) bool) {
				for i := range 3000 {
					if !yield(models.MatchResult{
						IsMatch: true,
						ID:      fmt.Sprintf("VULN-%d", i),
						Cursor:  nil, // Explicitly nil
					}, nil) {
						return
					}
				}
			}
		},
		get: func(_ context.Context, id string) (*osvschema.Vulnerability, error) {
			return &osvschema.Vulnerability{Id: id}, nil
		},
	}

	s := &server{
		vulnStore: store,
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param:   &pb.Query_Version{Version: "1.0.0"},
			Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
		},
	}

	got, err := s.QueryAffected(ctx, params)
	if err != nil {
		t.Fatalf("QueryAffected() unexpected error: %v", err)
	}

	// It should succeed and return the next page token as empty string (since cursor was nil)
	if got.GetNextPageToken() != "" {
		t.Errorf("Expected empty next page token, got %q", got.GetNextPageToken())
	}
}

func TestQueryAffected_MatcherPanicPropagation(t *testing.T) {
	ctx := context.Background()
	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(_ func(models.MatchResult, error) bool) {
				// Simulates a panic inside the database iterator loop (runMatcher)
				panic("matcher database crash")
			}
		},
	}

	s := &server{
		vulnStore: store,
	}

	params := &pb.QueryAffectedParameters{
		Query: &pb.Query{
			Param:   &pb.Query_Version{Version: "1.0.0"},
			Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
		},
	}

	_, err := s.QueryAffected(ctx, params)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("Expected gRPC code Internal, got %v", st.Code())
	}
	if !strings.Contains(st.Message(), "internal server error") {
		t.Errorf("Expected error message to contain 'internal server error', got %q", st.Message())
	}
}

func TestQueryAffectedBatch_WorkerPanicPropagation(t *testing.T) {
	ctx := context.Background()
	store := &mockQueryVulnStore{
		matchPackages: func(_ context.Context, _, _, _, _ string) iter.Seq2[models.MatchResult, error] {
			return func(_ func(models.MatchResult, error) bool) {
				// Simulates a panic inside the batch worker pipeline (QueryAffectedBatch worker)
				panic("batch worker crash")
			}
		},
	}

	s := &server{
		vulnStore: store,
	}

	params := &pb.QueryAffectedBatchParameters{
		Query: &pb.BatchQuery{
			Queries: []*pb.Query{
				{
					Param:   &pb.Query_Version{Version: "1.0.0"},
					Package: &osvschema.Package{Name: "pkg-1", Ecosystem: "npm"},
				},
			},
		},
	}

	_, err := s.QueryAffectedBatch(ctx, params)
	if err == nil {
		t.Fatalf("Expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("Expected gRPC status error, got %v", err)
	}
	if st.Code() != codes.Internal {
		t.Errorf("Expected gRPC code Internal, got %v", st.Code())
	}
	if !strings.Contains(st.Message(), "internal server error") {
		t.Errorf("Expected error message to contain 'internal server error', got %q", st.Message())
	}
}
