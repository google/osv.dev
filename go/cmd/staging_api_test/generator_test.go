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
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPayloadBuilders(t *testing.T) {
	//nolint:gosec // math/rand is sufficient for mock traffic generation
	rng := rand.New(rand.NewPCG(42, 42))
	vulnMap := map[string]*SimpleVuln{
		"OSV-001": {
			ID:            "OSV-001",
			Package:       "django",
			Ecosystem:     "PyPI",
			PURL:          "pkg:pypi/django",
			AffectedFuzzy: "3.2.1",
		},
	}

	t.Run("PackagePayload", func(t *testing.T) {
		payload, err := buildPackagePayload("OSV-001", vulnMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var q QueryPayload
		if err := json.Unmarshal(payload, &q); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if q.Package == nil || q.Package.Name != "django" || q.Package.Ecosystem != "PyPI" {
			t.Errorf("unexpected package payload: %+v", q)
		}
	})

	t.Run("VersionPayload", func(t *testing.T) {
		payload, err := buildVersionPayload("OSV-001", vulnMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var q QueryPayload
		if err := json.Unmarshal(payload, &q); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if q.Version != "3.2.1" || q.Package == nil || q.Package.Name != "django" {
			t.Errorf("unexpected version payload: %+v", q)
		}
	})

	t.Run("PURLPayload", func(t *testing.T) {
		payload, err := buildPURLPayload(rng, "OSV-001", vulnMap)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var q QueryPayload
		if err := json.Unmarshal(payload, &q); err != nil {
			t.Fatalf("failed to unmarshal payload: %v", err)
		}
		if q.Package == nil || (!strings.HasPrefix(q.Package.PURL, "pkg:pypi/django")) {
			t.Errorf("unexpected purl payload: %+v", q)
		}
	})

	t.Run("BatchPayload", func(t *testing.T) {
		payload, err := buildBatchPayload(rng, []string{"OSV-001"}, vulnMap, 10)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var b BatchQueryPayload
		if err := json.Unmarshal(payload, &b); err != nil {
			t.Fatalf("failed to unmarshal batch payload: %v", err)
		}
		if len(b.Queries) != 1 {
			t.Errorf("expected 1 query in batch, got %d", len(b.Queries))
		}
	})
}

func TestRunTrafficGenerator(t *testing.T) {
	var vulnCalls atomic.Int64
	var queryCalls atomic.Int64
	var batchCalls atomic.Int64

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		switch {
		case strings.HasPrefix(path, "/vulns/"):
			vulnCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"id":"OSV-001"}`))
		case path == "/query":
			queryCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"vulns":[]}`))
		case path == "/querybatch":
			batchCalls.Add(1)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"results":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	pools := &QueryPools{
		VulnMap: map[string]*SimpleVuln{
			"OSV-001": {
				ID:            "OSV-001",
				Package:       "express",
				Ecosystem:     "npm",
				PURL:          "pkg:npm/express",
				AffectedFuzzy: "4.17.1",
			},
		},
		VulnQueryIDs:       []string{"OSV-001"},
		PackageQueryIDs:    []string{"OSV-001"},
		LargeBatchQueryIDs: []string{"OSV-001"},
	}

	cfg := GeneratorConfig{
		BaseURL:                ts.URL,
		Duration:               200 * time.Millisecond,
		VulnRate:               20,
		VersionRate:            20,
		PackageRate:            20,
		PURLRate:               20,
		BatchRate:              10,
		LargeBatchRate:         10,
		MaxBatchQuerySize:      10,
		MaxLargeBatchQuerySize: 10,
		StatsInterval:          100 * time.Millisecond,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	stats, err := RunTrafficGenerator(ctx, ts.Client(), pools, cfg, 42)
	if err != nil {
		t.Fatalf("unexpected error running generator: %v", err)
	}

	if stats.SuccessCount.Load() == 0 {
		t.Errorf("expected at least 1 successful request, got %d", stats.SuccessCount.Load())
	}
	if vulnCalls.Load() == 0 {
		t.Errorf("expected vulnCalls > 0, got %d", vulnCalls.Load())
	}
	if queryCalls.Load() == 0 {
		t.Errorf("expected queryCalls > 0, got %d", queryCalls.Load())
	}
	if batchCalls.Load() == 0 {
		t.Errorf("expected batchCalls > 0, got %d", batchCalls.Load())
	}
}
