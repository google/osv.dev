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

package datastore

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
)

func TestUbuntuPackageMappingStore_GetAndPutMulti(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewUbuntuPackageMappingStore(dsClient)

	// Test empty GetMulti
	emptyResults, err := store.GetMulti(ctx, nil)
	if err != nil {
		t.Fatalf("GetMulti(nil) returned unexpected error: %v", err)
	}
	if len(emptyResults) != 0 {
		t.Fatalf("expected 0 results for empty GetMulti, got %d", len(emptyResults))
	}

	// Test empty PutMulti
	if err := store.PutMulti(ctx, nil); err != nil {
		t.Fatalf("PutMulti(nil) returned unexpected error: %v", err)
	}

	// Insert initial mappings
	initialMappings := []*models.UbuntuPackageMapping{
		{
			Ecosystem:   "Ubuntu:22.04:LTS",
			BinaryName:  "libglib2.0-0",
			SourceNames: []string{"glib2.0"},
		},
		{
			Ecosystem:   "Ubuntu:24.04",
			BinaryName:  "libglib2.0-bin",
			SourceNames: []string{"glib2.0"},
		},
		{
			Ecosystem:   "Ubuntu:22.04",
			BinaryName:  "shared-bin",
			SourceNames: []string{"src-a", "src-b"},
		},
	}

	if err := store.PutMulti(ctx, initialMappings); err != nil {
		t.Fatalf("PutMulti failed: %v", err)
	}

	// Query existing and non-existing binaries across normalized variants
	queried, err := store.GetMulti(ctx, []models.UbuntuPackageKey{
		{Ecosystem: "Ubuntu:22.04", BinaryName: "libglib2.0-0"},
		{Ecosystem: "Ubuntu:22.04", BinaryName: "nonexistent-pkg"},
		{Ecosystem: "Ubuntu:Pro:22.04:LTS", BinaryName: "shared-bin"},
	})
	if err != nil {
		t.Fatalf("GetMulti failed: %v", err)
	}

	expected := []*models.UbuntuPackageMapping{
		{
			Ecosystem:   "Ubuntu:22.04",
			BinaryName:  "libglib2.0-0",
			SourceNames: []string{"glib2.0"},
		},
		{
			Ecosystem:   "Ubuntu:22.04",
			BinaryName:  "nonexistent-pkg",
			SourceNames: []string{},
		},
		{
			Ecosystem:   "Ubuntu:22.04",
			BinaryName:  "shared-bin",
			SourceNames: []string{"src-a", "src-b"},
		},
	}

	if diff := cmp.Diff(expected, queried); diff != "" {
		t.Errorf("GetMulti mismatch (-want +got):\n%s", diff)
	}

	// Test update
	updateMappings := []*models.UbuntuPackageMapping{
		{
			Ecosystem:   "Ubuntu:22.04",
			BinaryName:  "libglib2.0-0",
			SourceNames: []string{"glib2.0", "glib2.0-esm"},
		},
	}
	if err := store.PutMulti(ctx, updateMappings); err != nil {
		t.Fatalf("PutMulti update failed: %v", err)
	}

	updated, err := store.GetMulti(ctx, []models.UbuntuPackageKey{
		{Ecosystem: "Ubuntu:22.04:LTS", BinaryName: "libglib2.0-0"},
	})
	if err != nil {
		t.Fatalf("GetMulti after update failed: %v", err)
	}
	expectedUpdate := []*models.UbuntuPackageMapping{
		{
			Ecosystem:   "Ubuntu:22.04",
			BinaryName:  "libglib2.0-0",
			SourceNames: []string{"glib2.0", "glib2.0-esm"},
		},
	}
	if diff := cmp.Diff(expectedUpdate, updated); diff != "" {
		t.Errorf("GetMulti update mismatch (-want +got):\n%s", diff)
	}
}

func TestUbuntuPackageMappingStore_BatchChunking(t *testing.T) {
	ctx := context.Background()
	dsClient := testutils.MustNewDatastoreClientForTesting(t)
	store := NewUbuntuPackageMappingStore(dsClient)

	// Create 550 entries to verify chunking (> 500 maxDatastorePutMultiBatchSize)
	total := 550
	mappings := make([]*models.UbuntuPackageMapping, total)
	keys := make([]models.UbuntuPackageKey, total)
	for i := range total {
		name := fmt.Sprintf("pkg-batch-%d", i)
		keys[i] = models.UbuntuPackageKey{
			Ecosystem:  "Ubuntu:24.04",
			BinaryName: name,
		}
		mappings[i] = &models.UbuntuPackageMapping{
			Ecosystem:   "Ubuntu:24.04",
			BinaryName:  name,
			SourceNames: []string{fmt.Sprintf("src-%d", i)},
		}
	}

	if err := store.PutMulti(ctx, mappings); err != nil {
		t.Fatalf("PutMulti chunking failed: %v", err)
	}

	queried, err := store.GetMulti(ctx, keys)
	if err != nil {
		t.Fatalf("GetMulti chunking failed: %v", err)
	}

	if len(queried) != total {
		t.Fatalf("expected %d queried mappings, got %d", total, len(queried))
	}
	for i := range total {
		if queried[i].BinaryName != keys[i].BinaryName {
			t.Errorf("index %d: expected name %q, got %q", i, keys[i].BinaryName, queried[i].BinaryName)
		}
		if len(queried[i].SourceNames) != 1 || queried[i].SourceNames[0] != fmt.Sprintf("src-%d", i) {
			t.Errorf("index %d: unexpected source names: %v", i, queried[i].SourceNames)
		}
	}
}
