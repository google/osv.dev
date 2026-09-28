// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package api

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/database/jsonstore"
	"github.com/google/osv.dev/go/internal/models"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/testing/protocmp"
	pb "osv.dev/bindings/go/api"
)

type mockUbuntuPackageMappingStore struct {
	mappings map[string][]string
	err      error
}

func (m *mockUbuntuPackageMappingStore) GetMulti(_ context.Context, binaryNames []string) ([]*models.UbuntuPackageMapping, error) {
	if m.err != nil {
		return nil, m.err
	}

	results := make([]*models.UbuntuPackageMapping, len(binaryNames))
	for i, name := range binaryNames {
		sources, ok := m.mappings[name]
		if !ok {
			sources = []string{}
		}
		results[i] = &models.UbuntuPackageMapping{
			BinaryName:  name,
			SourceNames: sources,
		}
	}

	return results, nil
}

func (m *mockUbuntuPackageMappingStore) PutMulti(_ context.Context, _ []*models.UbuntuPackageMapping) error {
	return nil
}

func TestQueryUbuntuPackageMapping(t *testing.T) {
	ctx := context.Background()

	mockStore := &mockUbuntuPackageMappingStore{
		mappings: map[string][]string{
			"libglib2.0-0":   {"glib2.0"},
			"libglib2.0-bin": {"glib2.0"},
			"shared-bin":     {"src-1", "src-2"},
		},
	}

	srv := &server{
		ubuntuPackageMappingStore: mockStore,
	}

	tests := []struct {
		name      string
		params    *pb.UbuntuPackageMappingParameters
		storeErr  error
		wantResp  *pb.UbuntuPackageMappingResponse
		wantCode  codes.Code
		wantError string
	}{
		{
			name: "Success with existing and non-existing binaries",
			params: &pb.UbuntuPackageMappingParameters{
				BinaryNames: []string{"libglib2.0-0", "unknown-binary", "shared-bin"},
			},
			wantResp: &pb.UbuntuPackageMappingResponse{
				Mappings: map[string]*pb.SourcePackages{
					"libglib2.0-0": {
						SourceNames: []string{"glib2.0"},
					},
					"unknown-binary": {
						SourceNames: []string{},
					},
					"shared-bin": {
						SourceNames: []string{"src-1", "src-2"},
					},
				},
			},
			wantCode: codes.OK,
		},
		{
			name:      "Empty binary names",
			params:    &pb.UbuntuPackageMappingParameters{BinaryNames: []string{}},
			wantCode:  codes.InvalidArgument,
			wantError: "binary_names is required",
		},
		{
			name:      "Nil parameters",
			params:    nil,
			wantCode:  codes.InvalidArgument,
			wantError: "binary_names is required",
		},
		{
			name: "Store failure propagates as internal error",
			params: &pb.UbuntuPackageMappingParameters{
				BinaryNames: []string{"libglib2.0-0"},
			},
			storeErr:  errors.New("connection failed"),
			wantCode:  codes.Internal,
			wantError: "failed to get ubuntu package mappings",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			mockStore.err = tc.storeErr
			resp, err := srv.QueryUbuntuPackageMapping(ctx, tc.params)

			if tc.wantCode == codes.OK {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if diff := cmp.Diff(tc.wantResp, resp, protocmp.Transform()); diff != "" {
					t.Errorf("QueryUbuntuPackageMapping mismatch (-want +got):\n%s", diff)
				}
			} else {
				if err == nil {
					t.Fatalf("expected error code %v, got nil", tc.wantCode)
				}
				st, ok := status.FromError(err)
				if !ok {
					t.Fatalf("expected gRPC status error, got %v", err)
				}
				if st.Code() != tc.wantCode {
					t.Errorf("expected status code %v, got %v", tc.wantCode, st.Code())
				}
				if tc.wantError != "" && !errors.Is(err, status.Error(st.Code(), st.Message())) && !cmp.Equal(st.Message(), tc.wantError) && !testing.Short() {
					// verify error message contains substring
					if !strings.Contains(st.Message(), tc.wantError) {
						t.Errorf("expected error message to contain %q, got %q", tc.wantError, st.Message())
					}
				}
			}
		})
	}
}

func TestQueryUbuntuPackageMapping_JSONStore(t *testing.T) {
	ctx := context.Background()
	tmpFile := filepath.Join(t.TempDir(), "mappings.json")

	store, err := jsonstore.New(tmpFile)
	if err != nil {
		t.Fatalf("failed to create JSONStore: %v", err)
	}

	if err := store.PutMulti(ctx, []*models.UbuntuPackageMapping{
		{BinaryName: "libglib2.0-0", SourceNames: []string{"glib2.0"}},
		{BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}); err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	srv := &server{
		ubuntuPackageMappingStore: store,
	}

	resp, err := srv.QueryUbuntuPackageMapping(ctx, &pb.UbuntuPackageMappingParameters{
		BinaryNames: []string{"libglib2.0-0", "libcurl4", "nonexistent"},
	})
	if err != nil {
		t.Fatalf("QueryUbuntuPackageMapping failed: %v", err)
	}

	wantResp := &pb.UbuntuPackageMappingResponse{
		Mappings: map[string]*pb.SourcePackages{
			"libglib2.0-0": {
				SourceNames: []string{"glib2.0"},
			},
			"libcurl4": {
				SourceNames: []string{"curl"},
			},
			"nonexistent": {
				SourceNames: []string{},
			},
		},
	}
	if diff := cmp.Diff(wantResp, resp, protocmp.Transform()); diff != "" {
		t.Errorf("QueryUbuntuPackageMapping with JSONStore mismatch (-want +got):\n%s", diff)
	}
}
