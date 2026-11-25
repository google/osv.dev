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

package worker

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/klauspost/compress/zstd"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"google.golang.org/protobuf/proto"
)

func TestParseVuln_JSON(t *testing.T) {
	sub := &Subscriber{}
	rawJSON := []byte(`{"id":"OSV-2026-1","summary":"test summary","unknown_field":"ignored"}`)

	t.Run("uncompressed json with format attribute", func(t *testing.T) {
		msg := &pubsub.Message{
			Data: rawJSON,
			Attributes: map[string]string{
				"format": "json",
			},
		}
		v, gotJSON, err := sub.parseVuln(msg)
		if err != nil {
			t.Fatalf("parseVuln() error = %v", err)
		}
		if v.GetId() != "OSV-2026-1" || v.GetSummary() != "test summary" {
			t.Errorf("parseVuln() vuln = %+v", v)
		}
		if string(gotJSON) != string(rawJSON) {
			t.Errorf("parseVuln() rawJSON = %q, want %q", gotJSON, rawJSON)
		}
	})

	t.Run("zstd-compressed json", func(t *testing.T) {
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatalf("zstd.NewWriter: %v", err)
		}
		compressed := enc.EncodeAll(rawJSON, nil)
		_ = enc.Close()

		msg := &pubsub.Message{
			Data: compressed,
			Attributes: map[string]string{
				"content_encoding": "zstd",
				"format":           "json",
			},
		}
		v, gotJSON, err := sub.parseVuln(msg)
		if err != nil {
			t.Fatalf("parseVuln() error = %v", err)
		}
		if v.GetId() != "OSV-2026-1" {
			t.Errorf("parseVuln() id = %q, want OSV-2026-1", v.GetId())
		}
		if string(gotJSON) != string(rawJSON) {
			t.Errorf("parseVuln() rawJSON = %q, want %q", gotJSON, rawJSON)
		}
	})

	t.Run("legacy protobuf fallback", func(t *testing.T) {
		orig := &osvschema.Vulnerability{
			Id:      "OSV-2026-2",
			Summary: "proto summary",
		}
		pbData, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}
		msg := &pubsub.Message{
			Data: pbData,
		}
		v, gotJSON, err := sub.parseVuln(msg)
		if err != nil {
			t.Fatalf("parseVuln() error = %v", err)
		}
		if v.GetId() != "OSV-2026-2" || v.GetSummary() != "proto summary" {
			t.Errorf("parseVuln() vuln = %+v", v)
		}
		if gotJSON != nil {
			t.Errorf("parseVuln() rawJSON = %q, want nil for protobuf message", gotJSON)
		}
	})

	t.Run("zstd payload exceeding max decoded memory", func(t *testing.T) {
		limitedSub := &Subscriber{
			MaxDecodedPayloadBytes: 1024,
		}
		largeJSON := append([]byte(`{"id":"OSV-2026-BIG","summary":"`), bytes.Repeat([]byte("a"), 4096)...)
		largeJSON = append(largeJSON, []byte(`"}`)...)
		compressed := zstd.EncodeTo(nil, largeJSON)

		msg := &pubsub.Message{
			Data: compressed,
			Attributes: map[string]string{
				"content_encoding": "zstd",
				"format":           "json",
			},
		}
		_, _, err := limitedSub.parseVuln(msg)
		if !errors.Is(err, zstd.ErrDecoderSizeExceeded) {
			t.Fatalf("parseVuln() error = %v, want wrapping %v", err, zstd.ErrDecoderSizeExceeded)
		}
	})
}

func scrapeMetricsText(t *testing.T) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	promhttp.Handler().ServeHTTP(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read /metrics body: %v", err)
	}

	return string(body)
}

func TestLogTaskLatencyRecordsImporterLag(t *testing.T) {
	const (
		defaultSource  = "test-default-source"
		reimportSource = "test-reimport-source"
		skewSource     = "test-clock-skew-source"
	)

	received := time.Now().Add(-3 * time.Second)
	logTaskLatency(t.Context(), Task{
		SourceID:     defaultSource,
		PathInSource: "VULN-1.json",
		ReceivedTime: &received,
	}, "default")

	// Reimport pool tasks must not be recorded into live ingestion latency.
	logTaskLatency(t.Context(), Task{
		SourceID:     reimportSource,
		PathInSource: "VULN-2.json",
		ReceivedTime: &received,
	}, "reimport")

	// Future ReceivedTime (cross-pod clock skew) should clamp to 0 without negative sum.
	future := time.Now().Add(5 * time.Second)
	logTaskLatency(t.Context(), Task{
		SourceID:     skewSource,
		PathInSource: "VULN-3.json",
		ReceivedTime: &future,
	}, "default")

	metricsOut := scrapeMetricsText(t)
	if !strings.Contains(metricsOut, `osv_worker_importer_to_available_seconds_count{source="test-default-source"} 1`) {
		t.Errorf("expected default source observation to be recorded, got:\n%s", metricsOut)
	}
	if strings.Contains(metricsOut, `source="test-reimport-source"`) {
		t.Errorf("expected reimport pool task not to be recorded, got:\n%s", metricsOut)
	}
	if !strings.Contains(metricsOut, `osv_worker_importer_to_available_seconds_bucket{source="test-clock-skew-source",le="1"} 1`) {
		t.Errorf("expected clock-skewed observation to be clamped into <=1s bucket, got:\n%s", metricsOut)
	}
	if !strings.Contains(metricsOut, `osv_worker_importer_to_available_seconds_sum{source="test-clock-skew-source"} 0`) {
		t.Errorf("expected clock-skewed observation sum to clamp to 0, got:\n%s", metricsOut)
	}
}
