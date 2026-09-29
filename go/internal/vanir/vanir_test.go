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

package vanir

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeVulnStore struct {
	models.UnimplementedVulnerabilityStore

	mu          sync.Mutex
	vulns       map[string]*osvschema.Vulnerability
	mutateErrs  map[string]error
	mutateCalls int
}

func newFakeVulnStore(vulns ...*osvschema.Vulnerability) *fakeVulnStore {
	m := make(map[string]*osvschema.Vulnerability, len(vulns))
	for _, v := range vulns {
		m[v.GetId()] = proto.CloneOf(v)
	}

	return &fakeVulnStore{
		vulns:      m,
		mutateErrs: make(map[string]error),
	}
}

func (s *fakeVulnStore) ListModifiedSince(_ context.Context, since *time.Time) iter.Seq2[*osvschema.Vulnerability, error] {
	return func(yield func(*osvschema.Vulnerability, error) bool) {
		s.mu.Lock()
		var list []*osvschema.Vulnerability
		for _, v := range s.vulns {
			if since != nil && !v.GetModified().AsTime().After(*since) {
				continue
			}
			list = append(list, proto.CloneOf(v))
		}
		s.mu.Unlock()

		slices.SortFunc(list, func(a, b *osvschema.Vulnerability) int {
			if a.GetId() < b.GetId() {
				return -1
			}
			if a.GetId() > b.GetId() {
				return 1
			}

			return 0
		})

		for _, v := range list {
			if !yield(v, nil) {
				return
			}
		}
	}
}

func (s *fakeVulnStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.vulns[id]
	if !ok {
		return nil, models.ErrNotFound
	}

	return proto.CloneOf(v), nil
}

func (s *fakeVulnStore) Mutate(_ context.Context, id string, mutateFn models.MutateFunc) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutateCalls++
	if err, ok := s.mutateErrs[id]; ok {
		return false, err
	}
	v, ok := s.vulns[id]
	if !ok {
		return false, models.ErrNotFound
	}
	cloned := proto.CloneOf(v)
	modified, err := mutateFn(cloned)
	if err != nil || !modified {
		return false, err
	}
	s.vulns[id] = cloned

	return true, nil
}

type fakeJobStore struct {
	mu   sync.Mutex
	data map[string]any
}

func newFakeJobStore() *fakeJobStore {
	return &fakeJobStore{
		data: make(map[string]any),
	}
}

func (s *fakeJobStore) Get(_ context.Context, key string, dst any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.data[key]
	if !ok {
		return models.ErrNotFound
	}
	reflect.ValueOf(dst).Elem().Set(reflect.ValueOf(v))

	return nil
}

func (s *fakeJobStore) Set(_ context.Context, key string, val any) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[key] = val

	return nil
}

type fakeGenerator struct {
	mu      sync.Mutex
	batches [][]*osvschema.Vulnerability
	results SignatureMap
}

func (g *fakeGenerator) GenerateBatch(_ context.Context, vulns []*osvschema.Vulnerability, _ string) (SignatureMap, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.batches = append(g.batches, slices.Clone(vulns))

	out := make(SignatureMap)
	for _, v := range vulns {
		if sigs, ok := g.results[v.GetId()]; ok {
			out[v.GetId()] = sigs
		}
	}

	return out, nil
}

func exampleSignatureValue(t *testing.T) *structpb.Value {
	t.Helper()
	val, err := structpb.NewValue(map[string]any{
		"id":                "MOCK-SIG-1",
		"signature_type":    "Function",
		"signature_version": "v1",
		"source":            "https://github.com/example/repo/commit/mock_commit_hash",
		"deprecated":        false,
	})
	if err != nil {
		t.Fatalf("structpb.NewValue: %v", err)
	}

	return val
}

func TestShouldProcess(t *testing.T) {
	sigVal := exampleSignatureValue(t)

	tests := []struct {
		name       string
		vuln       *osvschema.Vulnerability
		wantOK     bool
		wantReason string
	}{
		{
			name: "skip no git ranges",
			vuln: &osvschema.Vulnerability{
				Id:       "VULN-1",
				Affected: []*osvschema.Affected{{}},
			},
			wantOK:     false,
			wantReason: "no GIT affected ranges",
		},
		{
			name: "skip kernel package",
			vuln: &osvschema.Vulnerability{
				Id: "VULN-2",
				Affected: []*osvschema.Affected{
					{
						Package: &osvschema.Package{Name: "Kernel", Ecosystem: "Linux"},
						Ranges:  []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/kernel"}},
					},
				},
			},
			wantOK:     false,
			wantReason: "it is a Kernel vulnerability",
		},
		{
			name: "skip kernel repo URL",
			vuln: &osvschema.Vulnerability{
				Id: "VULN-3",
				Affected: []*osvschema.Affected{
					{
						Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git"}},
					},
				},
			},
			wantOK:     false,
			wantReason: "it is a Kernel vulnerability",
		},
		{
			name: "skip withdrawn",
			vuln: &osvschema.Vulnerability{
				Id:        "VULN-4",
				Withdrawn: timestamppb.New(time.Unix(1234567890, 0)),
				Affected: []*osvschema.Affected{
					{
						Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}},
					},
				},
			},
			wantOK:     false,
			wantReason: "it is withdrawn",
		},
		{
			name: "skip existing vanir signatures",
			vuln: &osvschema.Vulnerability{
				Id: "VULN-5",
				Affected: []*osvschema.Affected{
					{
						Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}},
						DatabaseSpecific: &structpb.Struct{
							Fields: map[string]*structpb.Value{
								"vanir_signatures": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{sigVal}}),
							},
						},
					},
				},
			},
			wantOK:     false,
			wantReason: "already has Vanir signatures",
		},
		{
			name: "eligible git vulnerability",
			vuln: &osvschema.Vulnerability{
				Id: "VULN-6",
				Affected: []*osvschema.Affected{
					{
						Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}},
					},
				},
			},
			wantOK:     true,
			wantReason: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotOK, gotReason := ShouldProcess(tc.vuln)
			if gotOK != tc.wantOK || gotReason != tc.wantReason {
				t.Errorf("ShouldProcess() = (%v, %q), want (%v, %q)", gotOK, gotReason, tc.wantOK, tc.wantReason)
			}
		})
	}
}

func TestRunner_SuccessPreservesUpstream(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)

	vuln := &osvschema.Vulnerability{
		Id:       "VULN-1",
		Upstream: []string{"CVE-2026-0001"},
		Modified: timestamppb.New(fixedNow.Add(-1 * time.Hour)),
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}},
			},
		},
	}

	vulnStore := newFakeVulnStore(vuln)
	jobStore := newFakeJobStore()
	sigVal := exampleSignatureValue(t)
	gen := &fakeGenerator{
		results: SignatureMap{
			"VULN-1": {
				0: {sigVal},
			},
		},
	}

	runner := &Runner{
		VulnStore: vulnStore,
		JobStore:  jobStore,
		Generator: gen,
		Config: Config{
			BatchSize:  100,
			MaxWorkers: 2,
			NowFunc:    func() time.Time { return fixedNow },
		},
	}

	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Runner.Run() failed: %v", err)
	}

	updated, err := vulnStore.GetFull(ctx, "VULN-1")
	if err != nil {
		t.Fatalf("GetFull(VULN-1) failed: %v", err)
	}

	if diff := cmp.Diff([]string{"CVE-2026-0001"}, updated.GetUpstream()); diff != "" {
		t.Errorf("Upstream was not preserved (-want +got):\n%s", diff)
	}

	if !updated.GetModified().AsTime().Equal(fixedNow) {
		t.Errorf("Modified = %v, want %v", updated.GetModified().AsTime(), fixedNow)
	}

	dbSpec := updated.GetAffected()[0].GetDatabaseSpecific().GetFields()
	if dbSpec["vanir_signatures_modified"].GetStringValue() != "2026-09-23T04:00:00Z" {
		t.Errorf("vanir_signatures_modified = %q, want 2026-09-23T04:00:00Z", dbSpec["vanir_signatures_modified"].GetStringValue())
	}

	gotSigs := dbSpec["vanir_signatures"].GetListValue().GetValues()
	if diff := cmp.Diff([]*structpb.Value{sigVal}, gotSigs, protocmp.Transform()); diff != "" {
		t.Errorf("vanir_signatures mismatch (-want +got):\n%s", diff)
	}

	lr, err := models.GetJobData[time.Time](ctx, jobStore, JobDataLastRun)
	if err != nil || !lr.Equal(fixedNow) {
		t.Errorf("last_run = (%v, %v), want %v", lr, err, fixedNow)
	}
}

func TestRunner_FailureAddsToRetryList(t *testing.T) {
	ctx := context.Background()
	fixedNow := time.Date(2026, 9, 23, 4, 0, 0, 0, time.UTC)

	vuln := &osvschema.Vulnerability{
		Id:       "VULN-FAIL",
		Modified: timestamppb.New(fixedNow.Add(-1 * time.Hour)),
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}},
			},
		},
	}

	vulnStore := newFakeVulnStore(vuln)
	vulnStore.mutateErrs["VULN-FAIL"] = errors.New("GCS precondition failed")
	jobStore := newFakeJobStore()
	gen := &fakeGenerator{
		results: SignatureMap{
			"VULN-FAIL": {
				0: {exampleSignatureValue(t)},
			},
		},
	}

	runner := &Runner{
		VulnStore: vulnStore,
		JobStore:  jobStore,
		Generator: gen,
		Config: Config{
			BatchSize:  100,
			MaxWorkers: 1,
			NowFunc:    func() time.Time { return fixedNow },
		},
	}

	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Runner.Run() failed: %v", err)
	}

	retryList, _ := models.GetJobData[[]string](ctx, jobStore, JobDataRetryList)
	if diff := cmp.Diff([]string{"VULN-FAIL"}, retryList); diff != "" {
		t.Errorf("retry_list mismatch (-want +got):\n%s", diff)
	}
}

func TestRunner_GlobalBatching(t *testing.T) {
	ctx := context.Background()
	vulns := make([]*osvschema.Vulnerability, 0, 150)
	for i := range 150 {
		vulns = append(vulns, &osvschema.Vulnerability{
			Id:       fmt.Sprintf("VULN-%03d", i),
			Modified: timestamppb.New(time.Now()),
			Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}},
				},
			},
		})
	}

	vulnStore := newFakeVulnStore(vulns...)
	jobStore := newFakeJobStore()
	gen := &fakeGenerator{}

	runner := &Runner{
		VulnStore: vulnStore,
		JobStore:  jobStore,
		Generator: gen,
		Config: Config{
			BatchSize:  100,
			MaxWorkers: 4,
			DryRun:     true,
		},
	}

	if err := runner.Run(ctx); err != nil {
		t.Fatalf("Runner.Run() failed: %v", err)
	}

	if len(gen.batches) != 2 {
		t.Fatalf("expected 2 batches, got %d", len(gen.batches))
	}
}

func TestPythonGenerator_GenerateBatch(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	scriptPath := filepath.Join(tempDir, "mock_vanir.py")
	scriptContent := `#!/usr/bin/env python3
import argparse, json
parser = argparse.ArgumentParser()
parser.add_argument('--input', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--git-working-dir', required=True)
args = parser.parse_args()
with open(args.input) as f:
    vulns = json.load(f)
out = {}
for v in vulns:
    out[v['id']] = {'0': [{'id': 'SIG-' + v['id'], 'signature_type': 'Function', 'signature_version': 'v1'}]}
with open(args.output, 'w') as f:
    json.dump(out, f)
`
	if err := os.WriteFile(scriptPath, []byte(scriptContent), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	gen := NewPythonGenerator("python3", scriptPath)
	vulns := []*osvschema.Vulnerability{
		{
			Id:       "VULN-IPC-1",
			Modified: timestamppb.New(time.Now()),
			Affected: []*osvschema.Affected{
				{Ranges: []*osvschema.Range{{Type: osvschema.Range_GIT, Repo: "https://example.com/repo"}}},
			},
		},
	}

	res, err := gen.GenerateBatch(ctx, vulns, tempDir)
	if err != nil {
		t.Fatalf("GenerateBatch failed: %v", err)
	}

	sigs := res["VULN-IPC-1"][0]
	if len(sigs) != 1 {
		t.Fatalf("expected 1 signature, got %d", len(sigs))
	}
	if gotID := sigs[0].GetStructValue().GetFields()["id"].GetStringValue(); gotID != "SIG-VULN-IPC-1" {
		t.Errorf("got signature ID %q, want SIG-VULN-IPC-1", gotID)
	}
}
