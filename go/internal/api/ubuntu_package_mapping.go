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
	"log/slog"

	"github.com/google/osv.dev/go/logger"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "osv.dev/bindings/go/api"
)

const (
	maxBinaryNames   = 1000
	maxBinaryNameLen = 256
)

// QueryUbuntuPackageMapping handles querying Ubuntu binary package names to retrieve their corresponding source package names.
func (s *server) QueryUbuntuPackageMapping(ctx context.Context, params *pb.UbuntuPackageMappingParameters) (*pb.UbuntuPackageMappingResponse, error) {
	if s.ubuntuPackageMappingStore == nil {
		return nil, status.Error(codes.Internal, "ubuntu package mapping store is not configured")
	}

	binaryNames := params.GetBinaryNames()
	if len(binaryNames) == 0 {
		return nil, status.Error(codes.InvalidArgument, "binary_names is required")
	}
	if len(binaryNames) > maxBinaryNames {
		return nil, status.Errorf(codes.InvalidArgument, "too many binary_names (max %d)", maxBinaryNames)
	}

	for i, name := range binaryNames {
		if name == "" || len(name) > maxBinaryNameLen {
			return nil, status.Errorf(codes.InvalidArgument, "invalid binary package name at index %d", i)
		}
	}

	if s.verboseLogs {
		logger.InfoContext(ctx, "querying ubuntu package mapping", slog.Any("binary_names", binaryNames))
	}

	// GetMulti returns a 1:1 slice matching binaryNames.
	mappings, err := s.ubuntuPackageMappingStore.GetMulti(ctx, binaryNames)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to get ubuntu package mappings: %v", err)
	}

	response := &pb.UbuntuPackageMappingResponse{
		Results: make([]*pb.SourcePackages, len(mappings)),
	}

	for i, m := range mappings {
		sourceNames := m.SourceNames
		if sourceNames == nil {
			sourceNames = []string{}
		}
		response.Results[i] = &pb.SourcePackages{
			SourceNames: sourceNames,
		}
	}

	return response, nil
}
