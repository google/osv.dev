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

const (
	// JobDataRecordCheckerInvalidRecords stores the list of invalid record IDs from the last recordchecker run.
	JobDataRecordCheckerInvalidRecords = "record_checker_invalid_records"
	// JobDataReconcilerSummary stores summary statistics from the last importer-reconciler run.
	JobDataReconcilerSummary = "importer_reconciler_summary"
	// JobDataDeleterSummary stores summary statistics from the last importer-deleter run.
	JobDataDeleterSummary = "importer_deleter_summary"
)

// ReconcilerSummary holds metrics from an importer-reconciler execution.
type ReconcilerSummary struct {
	LastRun       time.Time `json:"last_run"`
	UpToDateCount int64     `json:"up_to_date_count"`
	MissingCount  int64     `json:"missing_count"`
	OutdatedCount int64     `json:"outdated_count"`
}

// DeleterSummary holds metrics from an importer-deleter execution.
type DeleterSummary struct {
	LastRun           time.Time        `json:"last_run"`
	WithdrawnBySource map[string]int64 `json:"withdrawn_by_source"`
	RefusedBySource   map[string]int64 `json:"refused_by_source"`
}

// JobDataStore persists operational state (such as last run timestamps and retry lists) for background jobs.
type JobDataStore interface {
	// Get loads the value for key into dst (which must be a non-nil pointer).
	// Returns ErrNotFound if the key does not exist.
	Get(ctx context.Context, key string, dst any) error

	// Set persists val under key.
	Set(ctx context.Context, key string, val any) error
}

// GetJobData is a generic helper that retrieves and decodes a typed value from a JobDataStore.
func GetJobData[T any](ctx context.Context, store JobDataStore, key string) (T, error) {
	var val T
	err := store.Get(ctx, key, &val)

	return val, err
}
