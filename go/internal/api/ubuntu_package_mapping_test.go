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
	mappings map[models.UbuntuPackageKey][]string
	err      error
}

func (m *mockUbuntuPackageMappingStore) GetMulti(_ context.Context, keys []models.UbuntuPackageKey) ([]*models.UbuntuPackageMapping, error) {
	if m.err != nil {
		return nil, m.err
	}

	results := make([]*models.UbuntuPackageMapping, len(keys))
	for i, k := range keys {
		eco := models.NormalizeUbuntuEcosystem(k.Ecosystem)
		sources, ok := m.mappings[models.UbuntuPackageKey{Ecosystem: eco, BinaryName: k.BinaryName}]
		if !ok {
			sources = []string{}
		}
		results[i] = &models.UbuntuPackageMapping{
			Ecosystem:   eco,
			BinaryName:  k.BinaryName,
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
		mappings: map[models.UbuntuPackageKey][]string{
			{Ecosystem: "Ubuntu:22.04", BinaryName: "libglib2.0-0"}:   {"glib2.0"},
			{Ecosystem: "Ubuntu:22.04", BinaryName: "libglib2.0-bin"}: {"glib2.0"},
			{Ecosystem: "Ubuntu:22.04", BinaryName: "shared-bin"}:     {"src-1", "src-2"},
		},
	}

	srv := &server{
		ubuntuPackageMappingStore: mockStore,
	}

	tooManyNames := make([]string, maxBinaryNames+1)
	for i := range tooManyNames {
		tooManyNames[i] = "pkg"
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
			name: "Success with existing, duplicate, and non-existing binaries",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:22.04:LTS",
				BinaryNames: []string{"libglib2.0-0", "unknown-binary", "shared-bin", "libglib2.0-0"},
			},
			wantResp: &pb.UbuntuPackageMappingResponse{
				Results: []*pb.SourcePackages{
					{
						SourceNames: []string{"glib2.0"},
					},
					{
						SourceNames: []string{},
					},
					{
						SourceNames: []string{"src-1", "src-2"},
					},
					{
						SourceNames: []string{"glib2.0"},
					},
				},
			},
			wantCode: codes.OK,
		},
		{
			name: "Success with normalized Pro and bare release ecosystem",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:Pro:22.04:LTS",
				BinaryNames: []string{"libglib2.0-0"},
			},
			wantResp: &pb.UbuntuPackageMappingResponse{
				Results: []*pb.SourcePackages{
					{
						SourceNames: []string{"glib2.0"},
					},
				},
			},
			wantCode: codes.OK,
		},
		{
			name:      "Missing ecosystem",
			params:    &pb.UbuntuPackageMappingParameters{BinaryNames: []string{"libglib2.0-0"}},
			wantCode:  codes.InvalidArgument,
			wantError: "ecosystem is required",
		},
		{
			name: "Bare Ubuntu ecosystem without release suffix",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu",
				BinaryNames: []string{"libglib2.0-0"},
			},
			wantCode:  codes.InvalidArgument,
			wantError: "invalid ubuntu ecosystem",
		},
		{
			name: "Ubuntu ecosystem with only LTS or Pro modifier and no version",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:Pro:LTS",
				BinaryNames: []string{"libglib2.0-0"},
			},
			wantCode:  codes.InvalidArgument,
			wantError: "invalid ubuntu ecosystem",
		},
		{
			name: "Non-Ubuntu ecosystem",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Debian:12",
				BinaryNames: []string{"libglib2.0-0"},
			},
			wantCode:  codes.InvalidArgument,
			wantError: "invalid ubuntu ecosystem",
		},
		{
			name: "Empty binary names",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:22.04",
				BinaryNames: []string{},
			},
			wantCode:  codes.InvalidArgument,
			wantError: "binary_names is required",
		},
		{
			name:      "Nil parameters",
			params:    nil,
			wantCode:  codes.InvalidArgument,
			wantError: "ecosystem is required",
		},
		{
			name: "Empty string in binary names",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:22.04",
				BinaryNames: []string{"libglib2.0-0", ""},
			},
			wantCode:  codes.InvalidArgument,
			wantError: "invalid binary package name at index 1",
		},
		{
			name: "Too many binary names",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:22.04",
				BinaryNames: tooManyNames,
			},
			wantCode:  codes.InvalidArgument,
			wantError: "too many binary_names",
		},
		{
			name: "Store failure propagates as internal error",
			params: &pb.UbuntuPackageMappingParameters{
				Ecosystem:   "Ubuntu:22.04",
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
				if tc.wantError != "" && !strings.Contains(st.Message(), tc.wantError) {
					t.Errorf("expected error message to contain %q, got %q", tc.wantError, st.Message())
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
		{Ecosystem: "Ubuntu:24.04:LTS", BinaryName: "libglib2.0-0", SourceNames: []string{"glib2.0"}},
		{Ecosystem: "Ubuntu:24.04:LTS", BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}); err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	srv := &server{
		ubuntuPackageMappingStore: store,
	}

	resp, err := srv.QueryUbuntuPackageMapping(ctx, &pb.UbuntuPackageMappingParameters{
		Ecosystem:   "Ubuntu:24.04",
		BinaryNames: []string{"libglib2.0-0", "libcurl4", "nonexistent"},
	})
	if err != nil {
		t.Fatalf("QueryUbuntuPackageMapping failed: %v", err)
	}

	wantResp := &pb.UbuntuPackageMappingResponse{
		Results: []*pb.SourcePackages{
			{
				SourceNames: []string{"glib2.0"},
			},
			{
				SourceNames: []string{"curl"},
			},
			{
				SourceNames: []string{},
			},
		},
	}
	if diff := cmp.Diff(wantResp, resp, protocmp.Transform()); diff != "" {
		t.Errorf("QueryUbuntuPackageMapping with JSONStore mismatch (-want +got):\n%s", diff)
	}
}
