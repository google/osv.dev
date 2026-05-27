package api

import (
	"context"
	"errors"
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

type mockVulnerabilityStore struct {
	vuln *osvschema.Vulnerability
	err  error
}

func (m *mockVulnerabilityStore) Get(_ context.Context, _ string) (*osvschema.Vulnerability, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.vuln == nil {
		return nil, models.ErrNotFound
	}

	return m.vuln, nil
}

func (m *mockVulnerabilityStore) ListBySource(_ context.Context, _ string, _ bool) iter.Seq2[*models.VulnSourceRef, error] {
	panic("unimplemented")
}

func (m *mockVulnerabilityStore) GetSourceModified(_ context.Context, _ string) (time.Time, error) {
	panic("unimplemented")
}

func (m *mockVulnerabilityStore) GetWithMetadata(_ context.Context, _ string) (*osvschema.Vulnerability, *models.VulnSourceRef, error) {
	panic("unimplemented")
}

func (m *mockVulnerabilityStore) Write(_ context.Context, _ models.WriteRequest) error {
	panic("unimplemented")
}

type mockRelationsStore struct {
	aliases *models.GetAliasResult
	err     error
}

func (m *mockRelationsStore) GetAliases(_ context.Context, _ string) (*models.GetAliasResult, error) {
	if m.err != nil {
		return nil, m.err
	}
	if m.aliases == nil {
		return nil, models.ErrNotFound
	}

	return m.aliases, nil
}

func (m *mockRelationsStore) GetRelated(_ context.Context, _ string) (*models.GetRelatedResult, error) {
	panic("unimplemented")
}

func (m *mockRelationsStore) GetUpstream(_ context.Context, _ string) (*models.GetUpstreamResult, error) {
	panic("unimplemented")
}

func TestGetVulnById(t *testing.T) {
	ctx := context.Background()

	testVuln := &osvschema.Vulnerability{
		Id: "TEST-1",
	}

	tests := []struct {
		name           string
		id             string
		mockVuln       *osvschema.Vulnerability
		mockVulnErr    error
		mockAliases    *models.GetAliasResult
		mockAliasesErr error
		want           *osvschema.Vulnerability
		wantErrCode    codes.Code
		wantErrMsg     string
	}{
		{
			name:     "Success",
			id:       "TEST-1",
			mockVuln: testVuln,
			want:     testVuln,
		},
		{
			name:        "Empty ID",
			id:          "",
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "ID is required",
		},
		{
			name:        "Too Long ID",
			id:          string(make([]byte, 101)),
			wantErrCode: codes.InvalidArgument,
			wantErrMsg:  "ID is too long",
		},
		{
			name:        "Not Found - No Aliases",
			id:          "TEST-1",
			wantErrCode: codes.NotFound,
			wantErrMsg:  "Vulnerability not found",
		},
		{
			name: "Not Found - With Aliases",
			id:   "TEST-1",
			mockAliases: &models.GetAliasResult{
				Aliases: []string{"ALIAS-1", "ALIAS-2"},
			},
			wantErrCode: codes.NotFound,
			wantErrMsg:  "Vulnerability not found, but the following aliases were: ALIAS-1 ALIAS-2",
		},
		{
			name:        "VulnStore Error",
			id:          "TEST-1",
			mockVulnErr: errors.New("internal GCS error"),
			wantErrCode: codes.Internal,
			wantErrMsg:  "error getting vulnerability",
		},
		{
			name:           "RelationsStore Error",
			id:             "TEST-1",
			mockAliasesErr: errors.New("internal Datastore error"),
			wantErrCode:    codes.Internal,
			wantErrMsg:     "error getting vulnerability",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &server{
				vulnStore: &mockVulnerabilityStore{
					vuln: tt.mockVuln,
					err:  tt.mockVulnErr,
				},
				relationsStore: &mockRelationsStore{
					aliases: tt.mockAliases,
					err:     tt.mockAliasesErr,
				},
			}

			got, err := s.GetVulnById(ctx, &pb.GetVulnByIdParameters{Id: tt.id})

			if tt.wantErrCode != codes.OK {
				if err == nil {
					t.Fatalf("GetVulnById() expected error, got nil")
				}
				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("GetVulnById() expected gRPC status error, got %v", err)
				}
				if st.Code() != tt.wantErrCode {
					t.Errorf("GetVulnById() error code = %v, want %v", st.Code(), tt.wantErrCode)
				}
				if tt.wantErrMsg != "" && !strings.Contains(st.Message(), tt.wantErrMsg) {
					t.Errorf("GetVulnById() error message = %q, want to contain %q", st.Message(), tt.wantErrMsg)
				}
			} else {
				if err != nil {
					t.Fatalf("GetVulnById() unexpected error: %v", err)
				}
				if diff := cmp.Diff(tt.want, got, protocmp.Transform()); diff != "" {
					t.Errorf("GetVulnById() mismatch (-want +got):\n%s", diff)
				}
			}
		})
	}
}
