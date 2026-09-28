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
	"context"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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

func TestIsUbuntuRecord(t *testing.T) {
	tests := []struct {
		sourceID string
		id       string
		want     bool
	}{
		{"ubuntu-usn:osv/usn/USN-1.json", "USN-1", true},
		{"ubuntu-cve:osv/cve/CVE-2.json", "UBUNTU-CVE-2", true},
		{"ubuntu-lsn:osv/lsn/LSN-3.json", "LSN-3", true},
		{"debian:path/to/cve.json", "DSA-1234", false},
		{"", "USN-5000-1", true},
		{"", "UBUNTU-CVE-2024-1", true},
		{"", "LSN-001", true},
		{"", "GHSA-xxxx-yyyy", false},
	}

	for _, tc := range tests {
		got := isUbuntuRecord(tc.sourceID, tc.id)
		if got != tc.want {
			t.Errorf("isUbuntuRecord(%q, %q) = %v, want %v", tc.sourceID, tc.id, got, tc.want)
		}
	}
}

type mockFinder struct {
	ids []string
	err error
}

func (m *mockFinder) FindUbuntuVulnerabilities(_ context.Context, _ *time.Time) ([]string, error) {
	if m.err != nil {
		return nil, m.err
	}

	return m.ids, nil
}

type mockVulnStore struct {
	models.UnimplementedVulnerabilityStore

	vulns map[string]*osvschema.Vulnerability
}

func (m *mockVulnStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	if v, ok := m.vulns[id]; ok {
		return v, nil
	}

	return nil, models.ErrNotFound
}

type mockUbuntuStore struct {
	mu       sync.Mutex
	mappings map[string][]string
}

func newMockUbuntuStore() *mockUbuntuStore {
	return &mockUbuntuStore{mappings: make(map[string][]string)}
}

func (m *mockUbuntuStore) GetMulti(_ context.Context, binaryNames []string) ([]*models.UbuntuPackageMapping, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	results := make([]*models.UbuntuPackageMapping, len(binaryNames))
	for i, name := range binaryNames {
		srcs := m.mappings[name]
		if srcs == nil {
			srcs = []string{}
		}
		results[i] = &models.UbuntuPackageMapping{
			BinaryName:  name,
			SourceNames: srcs,
		}
	}

	return results, nil
}

func (m *mockUbuntuStore) PutMulti(_ context.Context, mappings []*models.UbuntuPackageMapping) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, item := range mappings {
		m.mappings[item.BinaryName] = item.SourceNames
	}

	return nil
}

type mockJobDataStore struct {
	mu      sync.Mutex
	lastRun *time.Time
}

func (m *mockJobDataStore) GetLastRun(_ context.Context, _ string) (time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lastRun == nil {
		return time.Time{}, models.ErrNotFound
	}

	return *m.lastRun, nil
}

func (m *mockJobDataStore) SetLastRun(_ context.Context, _ string, t time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRun = &t

	return nil
}

func TestRun_EndToEnd(t *testing.T) {
	ctx := context.Background()

	ecoStruct, err := structpb.NewStruct(map[string]any{
		"binaries": []any{
			map[string]any{"binary_name": "libcurl4"},
			map[string]any{"binary_name": "curl"},
		},
	})
	if err != nil {
		t.Fatalf("failed to create ecoStruct: %v", err)
	}

	vuln1 := &osvschema.Vulnerability{
		Id: "USN-1-1",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Name: "curl",
				},
				EcosystemSpecific: ecoStruct,
			},
		},
	}

	finder := &mockFinder{ids: []string{"USN-1-1"}}
	vulnStore := &mockVulnStore{
		vulns: map[string]*osvschema.Vulnerability{
			"USN-1-1": vuln1,
		},
	}
	ubuntuStore := newMockUbuntuStore()
	jobDataStore := &mockJobDataStore{}

	env := &appEnv{
		finder:       finder,
		vulnStore:    vulnStore,
		ubuntuStore:  ubuntuStore,
		jobDataStore: jobDataStore,
		numWorkers:   2,
	}

	// 1. Initial run
	if err := run(ctx, env); err != nil {
		t.Fatalf("run failed: %v", err)
	}

	if jobDataStore.lastRun == nil {
		t.Fatal("expected jobDataStore.lastRun to be set, was nil")
	}

	expectedMappings := map[string][]string{
		"curl":     {"curl"},
		"libcurl4": {"curl"},
	}
	if diff := cmp.Diff(expectedMappings, ubuntuStore.mappings); diff != "" {
		t.Errorf("mappings mismatch (-want +got):\n%s", diff)
	}

	// 2. Incremental run adding another source to libcurl4
	ecoStruct2, _ := structpb.NewStruct(map[string]any{
		"binaries": []any{
			map[string]any{"binary_name": "libcurl4"},
			map[string]any{"binary_name": "curl-esm"},
		},
	})
	vuln2 := &osvschema.Vulnerability{
		Id: "USN-2-1",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Name: "curl-esm-src",
				},
				EcosystemSpecific: ecoStruct2,
			},
		},
	}
	vulnStore.vulns["USN-2-1"] = vuln2
	finder.ids = []string{"USN-2-1"}

	if err := run(ctx, env); err != nil {
		t.Fatalf("incremental run failed: %v", err)
	}

	expectedAfterMerge := map[string][]string{
		"curl":     {"curl"},
		"libcurl4": {"curl", "curl-esm-src"},
		"curl-esm": {"curl-esm-src"},
	}
	if diff := cmp.Diff(expectedAfterMerge, ubuntuStore.mappings); diff != "" {
		t.Errorf("mappings mismatch after merge (-want +got):\n%s", diff)
	}
}
