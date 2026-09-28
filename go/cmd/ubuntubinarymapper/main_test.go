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

package main

import (
	"archive/zip"
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/database/jsonstore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestExtractBinaryMappings(t *testing.T) {
	ecoStruct, err := structpb.NewStruct(map[string]any{
		"binaries": []any{
			map[string]any{
				"binary_name":    "libglib2.0-0",
				"binary_version": "2.40.2",
			},
			map[string]any{
				"binary_name":    "libglib2.0-bin",
				"binary_version": "2.40.2",
			},
			"simple-string-bin",
		},
	})
	if err != nil {
		t.Fatalf("failed to create ecoStruct: %v", err)
	}

	dbStruct, err := structpb.NewStruct(map[string]any{
		"binaries": []any{
			map[string]any{
				"name": "db-specific-bin",
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to create dbStruct: %v", err)
	}

	vuln := &osvschema.Vulnerability{
		Id: "USN-1000-1",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Name:      "glib2.0",
					Ecosystem: "Ubuntu:22.04:LTS",
				},
				EcosystemSpecific: ecoStruct,
				DatabaseSpecific:  dbStruct,
			},
			{
				Package: &osvschema.Package{
					Name:      "empty-pkg",
					Ecosystem: "Ubuntu:22.04:LTS",
				},
			},
		},
	}

	got := ExtractBinaryMappings(vuln)

	expected := map[string]map[string]struct{}{
		"libglib2.0-0": {
			"glib2.0": struct{}{},
		},
		"libglib2.0-bin": {
			"glib2.0": struct{}{},
		},
		"simple-string-bin": {
			"glib2.0": struct{}{},
		},
		"db-specific-bin": {
			"glib2.0": struct{}{},
		},
	}

	if diff := cmp.Diff(expected, got); diff != "" {
		t.Errorf("ExtractBinaryMappings mismatch (-want +got):\n%s", diff)
	}
}

func TestFindModifiedUbuntuIDs(t *testing.T) {
	ctx := context.Background()
	memGCS := testutils.NewMockStorage()

	csvContent := "2026-09-22T10:00:00Z,USN-3-1\n" +
		"2026-09-21T10:00:00Z,USN-2-1\n" +
		"2026-09-20T10:00:00Z,USN-1-1\n"

	if err := memGCS.WriteObject(ctx, ubuntuModifiedCSVPath, []byte(csvContent), nil); err != nil {
		t.Fatalf("failed writing modified_id.csv: %v", err)
	}

	// 1. Nil lastRun should return all 3 IDs
	allIDs, err := findModifiedUbuntuIDs(ctx, memGCS, nil)
	if err != nil {
		t.Fatalf("findModifiedUbuntuIDs(nil) failed: %v", err)
	}
	if diff := cmp.Diff([]string{"USN-3-1", "USN-2-1", "USN-1-1"}, allIDs); diff != "" {
		t.Errorf("findModifiedUbuntuIDs(nil) mismatch (-want +got):\n%s", diff)
	}

	// 2. lastRun at 2026-09-21T00:00:00Z should return USN-3-1 and USN-2-1
	cutoff, err := time.Parse(time.RFC3339, "2026-09-21T00:00:00Z")
	if err != nil {
		t.Fatalf("failed parsing cutoff: %v", err)
	}
	filteredIDs, err := findModifiedUbuntuIDs(ctx, memGCS, &cutoff)
	if err != nil {
		t.Fatalf("findModifiedUbuntuIDs(cutoff) failed: %v", err)
	}
	if diff := cmp.Diff([]string{"USN-3-1", "USN-2-1"}, filteredIDs); diff != "" {
		t.Errorf("findModifiedUbuntuIDs(cutoff) mismatch (-want +got):\n%s", diff)
	}
}

func mustMarshalVuln(t *testing.T, v *osvschema.Vulnerability) []byte {
	t.Helper()
	b, err := protojson.Marshal(v)
	if err != nil {
		t.Fatalf("failed marshaling vuln: %v", err)
	}

	return b
}

func createZipArchive(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("failed creating %s in zip: %v", name, err)
		}
		if _, err := w.Write(content); err != nil {
			t.Fatalf("failed writing %s in zip: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("failed closing zip: %v", err)
	}

	return buf.Bytes()
}

func TestRun_EndToEnd(t *testing.T) {
	ctx := context.Background()
	memGCS := testutils.NewMockStorage()
	ubuntuStore := jsonstore.NewInMemory()

	ecoStruct1, err := structpb.NewStruct(map[string]any{
		"binaries": []any{
			map[string]any{"binary_name": "libcurl4"},
			map[string]any{"binary_name": "curl"},
		},
	})
	if err != nil {
		t.Fatalf("failed to create ecoStruct1: %v", err)
	}

	vuln1 := &osvschema.Vulnerability{
		Id: "USN-1-1",
		Affected: []*osvschema.Affected{
			{
				Package:           &osvschema.Package{Name: "curl"},
				EcosystemSpecific: ecoStruct1,
			},
		},
	}

	ecoStruct2, err := structpb.NewStruct(map[string]any{
		"binaries": []any{
			map[string]any{"binary_name": "libcurl4"},
			map[string]any{"binary_name": "curl-esm"},
		},
	})
	if err != nil {
		t.Fatalf("failed to create ecoStruct2: %v", err)
	}

	vuln2 := &osvschema.Vulnerability{
		Id: "USN-2-1",
		Affected: []*osvschema.Affected{
			{
				Package:           &osvschema.Package{Name: "curl-esm-src"},
				EcosystemSpecific: ecoStruct2,
			},
		},
	}

	vuln1Bytes := mustMarshalVuln(t, vuln1)
	vuln2Bytes := mustMarshalVuln(t, vuln2)

	// Upload Ubuntu/all.zip containing both USN-1-1.json and USN-2-1.json
	zipBytes := createZipArchive(t, map[string][]byte{
		"USN-1-1.json": vuln1Bytes,
		"USN-2-1.json": vuln2Bytes,
	})
	if err := memGCS.WriteObject(ctx, ubuntuAllZipPath, zipBytes, nil); err != nil {
		t.Fatalf("failed writing all.zip: %v", err)
	}

	// Upload individual JSON files as well
	if err := memGCS.WriteObject(ctx, "Ubuntu/USN-2-1.json", vuln2Bytes, nil); err != nil {
		t.Fatalf("failed writing Ubuntu/USN-2-1.json: %v", err)
	}

	// 1. Initial run with 2 records and zipThreshold=1 (forces Ubuntu/all.zip path, processing only USN-1-1)
	if err := memGCS.WriteObject(ctx, ubuntuModifiedCSVPath, []byte("2026-09-20T12:00:00Z,USN-1-1\n2026-09-19T12:00:00Z,USN-0-1\n"), nil); err != nil {
		t.Fatalf("failed writing modified_id.csv: %v", err)
	}

	env := &appEnv{
		gcsStorage:   memGCS,
		ubuntuStore:  ubuntuStore,
		numWorkers:   2,
		zipThreshold: 1,
	}

	if err := run(ctx, env); err != nil {
		t.Fatalf("initial run failed: %v", err)
	}

	got, err := ubuntuStore.GetMulti(ctx, []string{"curl", "libcurl4"})
	if err != nil {
		t.Fatalf("GetMulti failed: %v", err)
	}
	wantInitial := []*models.UbuntuPackageMapping{
		{BinaryName: "curl", SourceNames: []string{"curl"}},
		{BinaryName: "libcurl4", SourceNames: []string{"curl"}},
	}
	if diff := cmp.Diff(wantInitial, got); diff != "" {
		t.Errorf("initial mappings mismatch (-want +got):\n%s", diff)
	}

	// 2. Incremental run with localLastRun set so only 1 record (USN-2-1) matches, using individual file download path
	if err := memGCS.WriteObject(ctx, ubuntuModifiedCSVPath, []byte("2026-09-22T12:00:00Z,USN-2-1\n2026-09-20T12:00:00Z,USN-1-1\n"), nil); err != nil {
		t.Fatalf("failed updating modified_id.csv: %v", err)
	}
	lastRun, _ := time.Parse(time.RFC3339, "2026-09-21T00:00:00Z")
	env.localLastRun = &lastRun
	env.zipThreshold = 10

	if err := run(ctx, env); err != nil {
		t.Fatalf("incremental run failed: %v", err)
	}

	gotAfter, err := ubuntuStore.GetMulti(ctx, []string{"curl", "libcurl4", "curl-esm"})
	if err != nil {
		t.Fatalf("GetMulti after incremental run failed: %v", err)
	}
	wantAfter := []*models.UbuntuPackageMapping{
		{BinaryName: "curl", SourceNames: []string{"curl"}},
		{BinaryName: "libcurl4", SourceNames: []string{"curl", "curl-esm-src"}},
		{BinaryName: "curl-esm", SourceNames: []string{"curl-esm-src"}},
	}
	if diff := cmp.Diff(wantAfter, gotAfter); diff != "" {
		t.Errorf("mappings mismatch after incremental merge (-want +got):\n%s", diff)
	}
}
