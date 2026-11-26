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
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
)

func TestJSONStore_InMemory(t *testing.T) {
	ctx := context.Background()
	store, err := New("")
	if err != nil {
		t.Fatalf("New(\"\") failed: %v", err)
	}

	// Initial GetMulti should return empty SourceNames
	initial, err := store.GetMulti(ctx, []models.UbuntuPackageKey{
		{Ecosystem: "Ubuntu:24.04", BinaryName: "pkg-a"},
		{Ecosystem: "Ubuntu:24.04", BinaryName: "pkg-b"},
	})
	if err != nil {
		t.Fatalf("GetMulti failed: %v", err)
	}
	if len(initial) != 2 {
		t.Fatalf("expected 2 items, got %d", len(initial))
	}
	if len(initial[0].SourceNames) != 0 || len(initial[1].SourceNames) != 0 {
		t.Errorf("expected empty source names, got %v, %v", initial[0].SourceNames, initial[1].SourceNames)
	}

	// Put mappings
	err = store.PutMulti(ctx, []*models.UbuntuPackageMapping{
		{Ecosystem: "Ubuntu:24.04:LTS", BinaryName: "pkg-a", SourceNames: []string{"src-1"}},
		{Ecosystem: "Ubuntu:Pro:22.04:LTS", BinaryName: "pkg-b", SourceNames: []string{"src-2", "src-1"}},
	})
	if err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	// Verify GetMulti returns sorted, deduplicated sources with normalized ecosystems
	queried, err := store.GetMulti(ctx, []models.UbuntuPackageKey{
		{Ecosystem: "Ubuntu:22.04", BinaryName: "pkg-b"},
		{Ecosystem: "Ubuntu:24.04", BinaryName: "pkg-a"},
		{Ecosystem: "Ubuntu:24.04", BinaryName: "unknown"},
	})
	if err != nil {
		t.Fatalf("GetMulti failed: %v", err)
	}

	expected := []*models.UbuntuPackageMapping{
		{Ecosystem: "Ubuntu:22.04", BinaryName: "pkg-b", SourceNames: []string{"src-1", "src-2"}},
		{Ecosystem: "Ubuntu:24.04", BinaryName: "pkg-a", SourceNames: []string{"src-1"}},
		{Ecosystem: "Ubuntu:24.04", BinaryName: "unknown", SourceNames: []string{}},
	}
	if diff := cmp.Diff(expected, queried); diff != "" {
		t.Errorf("GetMulti mismatch (-want +got):\n%s", diff)
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

	if err := store1.PutMulti(ctx, []*models.UbuntuPackageMapping{
		{Ecosystem: "Ubuntu:24.04:LTS", BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}); err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	// Create a second store pointing to the same file to verify persistence and loading
	store2, err := New(filePath)
	if err != nil {
		t.Fatalf("New on existing file failed: %v", err)
	}

	queried, err := store2.GetMulti(ctx, []models.UbuntuPackageKey{
		{Ecosystem: "Ubuntu:24.04", BinaryName: "libcurl4"},
	})
	if err != nil {
		t.Fatalf("store2 GetMulti failed: %v", err)
	}
	expected := []*models.UbuntuPackageMapping{
		{Ecosystem: "Ubuntu:24.04", BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}
	if diff := cmp.Diff(expected, queried); diff != "" {
		t.Errorf("store2 mismatch (-want +got):\n%s", diff)
	}
}
