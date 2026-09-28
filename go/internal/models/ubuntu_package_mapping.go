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

package models

import (
	"context"
	"time"
)

// UbuntuPackageMapping represents the mapping from an Ubuntu binary package name
// to its corresponding source package names.
type UbuntuPackageMapping struct {
	BinaryName  string
	SourceNames []string
}

// UbuntuPackageMappingStore abstracts database operations for querying and updating
// Ubuntu binary-to-source package name mappings.
type UbuntuPackageMappingStore interface {
	// GetMulti retrieves mappings for a slice of binary package names.
	// For any binary package not found, the returned UbuntuPackageMapping has an empty SourceNames slice.
	GetMulti(ctx context.Context, binaryNames []string) ([]*UbuntuPackageMapping, error)

	// PutMulti creates or updates package mappings for multiple binary package names.
	PutMulti(ctx context.Context, mappings []*UbuntuPackageMapping) error
}

// JobDataStore abstracts storage operations for job execution metadata and checkpoints.
type JobDataStore interface {
	// GetLastRun retrieves the last execution time for a given job ID.
	// If no prior execution record exists, returns time.Time{} and ErrNotFound.
	GetLastRun(ctx context.Context, jobID string) (time.Time, error)

	// SetLastRun records the execution time for a given job ID.
	SetLastRun(ctx context.Context, jobID string, t time.Time) error
}
