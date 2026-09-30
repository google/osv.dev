// Copyright 2026 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"context"
	"testing"
	"time"
)

func TestMemJobStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemJobStore()
	defer store.Close()

	// Initial retrieval should return nil
	lastRun, err := store.GetLastRun(ctx, "test_job")
	if err != nil {
		t.Fatalf("unexpected error getting last run: %v", err)
	}
	if lastRun != nil {
		t.Fatalf("expected nil last run, got %v", lastRun)
	}

	// Record a timestamp
	now := time.Date(2026, 9, 22, 12, 0, 0, 0, time.UTC)
	if err := store.SetLastRun(ctx, "test_job", now); err != nil {
		t.Fatalf("unexpected error setting last run: %v", err)
	}

	// Retrieve recorded timestamp
	got, err := store.GetLastRun(ctx, "test_job")
	if err != nil {
		t.Fatalf("unexpected error getting last run after set: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil last run, got nil")
	}
	if !got.Equal(now) {
		t.Fatalf("expected time %v, got %v", now, *got)
	}

	// Overwrite timestamp
	later := now.Add(6 * time.Hour)
	if err := store.SetLastRun(ctx, "test_job", later); err != nil {
		t.Fatalf("unexpected error updating last run: %v", err)
	}

	gotLater, err := store.GetLastRun(ctx, "test_job")
	if err != nil {
		t.Fatalf("unexpected error getting updated last run: %v", err)
	}
	if gotLater == nil || !gotLater.Equal(later) {
		t.Fatalf("expected time %v, got %v", later, gotLater)
	}

	// Another job ID remains empty
	other, err := store.GetLastRun(ctx, "other_job")
	if err != nil {
		t.Fatalf("unexpected error getting other job: %v", err)
	}
	if other != nil {
		t.Fatalf("expected other_job to be nil, got %v", other)
	}
}
