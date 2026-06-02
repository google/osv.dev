package api

import (
	"context"
	"iter"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
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

func (m *mockQueryVulnStore) Get(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
	if m.get != nil {
		return m.get(ctx, id)
	}

	return nil, models.ErrNotFound
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
		get: func(_ context.Context, id string) (*osvschema.Vulnerability, error) {
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
