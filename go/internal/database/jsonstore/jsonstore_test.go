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

package jsonstore

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
)

func TestJSONStore_InMemory(t *testing.T) {
	ctx := context.Background()
	store := NewInMemory()

	// Initial GetMulti should return empty SourceNames
	initial, err := store.GetMulti(ctx, []string{"pkg-a", "pkg-b"})
	if err != nil {
		t.Fatalf("GetMulti failed: %v", err)
	}
	if len(initial) != 2 {
		t.Fatalf("expected 2 items, got %d", len(initial))
	}
	if len(initial[0].SourceNames) != 0 || len(initial[1].SourceNames) != 0 {
		t.Errorf("expected empty source names, got %v, %v", initial[0].SourceNames, initial[1].SourceNames)
	}

	// Initial GetLastRun should return ErrNotFound
	_, err = store.GetLastRun(ctx, "job1")
	if !errors.Is(err, models.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}

	// Put mappings
	err = store.PutMulti(ctx, []*models.UbuntuPackageMapping{
		{BinaryName: "pkg-a", SourceNames: []string{"src-1"}},
		{BinaryName: "pkg-b", SourceNames: []string{"src-2", "src-1"}},
	})
	if err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	// Verify GetMulti returns sorted, deduplicated sources
	queried, err := store.GetMulti(ctx, []string{"pkg-b", "pkg-a", "unknown"})
	if err != nil {
		t.Fatalf("GetMulti failed: %v", err)
	}

	expected := []*models.UbuntuPackageMapping{
		{BinaryName: "pkg-b", SourceNames: []string{"src-1", "src-2"}},
		{BinaryName: "pkg-a", SourceNames: []string{"src-1"}},
		{BinaryName: "unknown", SourceNames: []string{}},
	}
	if diff := cmp.Diff(expected, queried); diff != "" {
		t.Errorf("GetMulti mismatch (-want +got):\n%s", diff)
	}

	// Set and get last run
	now := time.Now().UTC().Truncate(time.Second)
	if err := store.SetLastRun(ctx, "job1", now); err != nil {
		t.Fatalf("SetLastRun failed: %v", err)
	}

	lastRun, err := store.GetLastRun(ctx, "job1")
	if err != nil {
		t.Fatalf("GetLastRun failed: %v", err)
	}
	if !lastRun.Equal(now) {
		t.Errorf("expected %v, got %v", now, lastRun)
	}
}

func TestJSONStore_FilePersistence(t *testing.T) {
	ctx := context.Background()
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sub", "test_store.json")

	store1, err := New(filePath)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}

	now := time.Now().UTC().Truncate(time.Second)
	if err := store1.SetLastRun(ctx, "jobA", now); err != nil {
		t.Fatalf("SetLastRun failed: %v", err)
	}

	if err := store1.PutMulti(ctx, []*models.UbuntuPackageMapping{
		{BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}); err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	// Create a second store pointing to the same file to verify persistence and loading
	store2, err := New(filePath)
	if err != nil {
		t.Fatalf("New on existing file failed: %v", err)
	}

	lastRun, err := store2.GetLastRun(ctx, "jobA")
	if err != nil {
		t.Fatalf("store2 GetLastRun failed: %v", err)
	}
	if !lastRun.Equal(now) {
		t.Errorf("store2 expected last run %v, got %v", now, lastRun)
	}

	queried, err := store2.GetMulti(ctx, []string{"libcurl4"})
	if err != nil {
		t.Fatalf("store2 GetMulti failed: %v", err)
	}
	expected := []*models.UbuntuPackageMapping{
		{BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}
	if diff := cmp.Diff(expected, queried); diff != "" {
		t.Errorf("store2 mismatch (-want +got):\n%s", diff)
	}
}
