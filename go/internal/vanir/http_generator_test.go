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
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

func testVuln(id string) *osvschema.Vulnerability {
	return &osvschema.Vulnerability{
		Id: id,
		Affected: []*osvschema.Affected{{
			Ranges: []*osvschema.Range{{
				Type:   osvschema.Range_GIT,
				Repo:   "https://github.com/example/repo",
				Events: []*osvschema.Event{{Fixed: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
			}},
		}},
	}
}

func TestHTTPSignatureGenerator(t *testing.T) {
	sandbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/generate" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var req sandboxGenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
		}
		var v struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(req.Vulnerability, &v); err != nil {
			t.Errorf("unmarshal vulnerability: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		switch v.ID {
		case "OSV-BAD-IDX":
			_, _ = w.Write([]byte(`{"signatures":{"99":[{"id":"OSV-BAD-IDX-1","signature_type":"Function","signature_version":"v1"}]}}`))
		case "OSV-NONCANON-IDX":
			_, _ = w.Write([]byte(`{"signatures":{"00":[{"id":"OSV-NONCANON-IDX-1","signature_type":"Function","signature_version":"v1"}]}}`))
		case "OSV-BAD-SIG":
			_, _ = w.Write([]byte(`{"signatures":{"0":[{"id":"OSV-BAD-SIG-1"}]}}`))
		case "OSV-EMPTY":
			_, _ = w.Write([]byte(`{"signatures":{}}`))
		default:
			_, _ = fmt.Fprintf(w, `{"signatures":{"0":[{"id":"%s-11223344","signature_type":"Function","signature_version":"v1"}]}}`, v.ID)
		}
	}))
	t.Cleanup(sandbox.Close)

	gen := &HTTPSignatureGenerator{SandboxURL: sandbox.URL, HTTPClient: sandbox.Client()}
	got, err := gen.GenerateBatch(context.Background(), []*osvschema.Vulnerability{
		testVuln("GHSA-aaaa-bbbb-cccc"),
		testVuln("OSV-BAD-IDX"),
		testVuln("OSV-NONCANON-IDX"),
		testVuln("OSV-BAD-SIG"),
		testVuln("OSV-EMPTY"),
	}, "")
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	sigs := got["GHSA-aaaa-bbbb-cccc"][0]
	if len(sigs) != 1 || sigs[0].GetStructValue().GetFields()["id"].GetStringValue() != "GHSA-aaaa-bbbb-cccc-11223344" {
		t.Errorf("unexpected valid signature: %+v", sigs)
	}
	for _, skipped := range []string{"OSV-BAD-IDX", "OSV-NONCANON-IDX", "OSV-BAD-SIG", "OSV-EMPTY"} {
		if _, ok := got[skipped]; ok {
			t.Errorf("expected %s to be omitted from results", skipped)
		}
	}
}

func TestHTTPSignatureGenerator_RetriesAndErrors(t *testing.T) {
	for _, badURL := range []string{
		"",
		"http://insecure.example.com",
		"https://user:pass@example.com",
		"https://example.com/v1/generate",
		"https://example.com?foo=bar",
		"https://example.com#frag",
	} {
		if _, err := NewHTTPSignatureGenerator(context.Background(), badURL); err == nil {
			t.Errorf("expected error for invalid sandboxURL %q", badURL)
		}
	}

	// Retries transient 503 and succeeds.
	var attempts atomic.Int32
	flaky := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if attempts.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte("sandbox busy"))

			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"signatures":{"0":[{"id":"OSV-RETRY-1","signature_type":"Function","signature_version":"v1"}]}}`))
	}))
	t.Cleanup(flaky.Close)
	gen := &HTTPSignatureGenerator{SandboxURL: flaky.URL, HTTPClient: flaky.Client(), retryBackoff: time.Millisecond}
	got, err := gen.GenerateBatch(context.Background(), []*osvschema.Vulnerability{testVuln("OSV-RETRY")}, "")
	if err != nil || len(got["OSV-RETRY"][0]) != 1 || attempts.Load() != 3 {
		t.Fatalf("retry failed: got=%+v err=%v attempts=%d", got, err, attempts.Load())
	}

	// Refuses both 302 (POST->GET) and 307 redirects via CheckRedirect: refuseRedirects.
	for _, code := range []int{http.StatusFound, http.StatusTemporaryRedirect} {
		var redirectHit atomic.Bool
		target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			redirectHit.Store(true)
			w.WriteHeader(http.StatusOK)
		}))
		t.Cleanup(target.Close)
		redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL, code)
		}))
		t.Cleanup(redir.Close)

		_, err := (&HTTPSignatureGenerator{SandboxURL: redir.URL}).GenerateBatch(context.Background(), []*osvschema.Vulnerability{testVuln("OSV-REDIR")}, "")
		if err == nil || redirectHit.Load() || !strings.Contains(err.Error(), fmt.Sprintf("status %d", code)) {
			t.Errorf("redirect %d should be refused without hitting target (err=%v hit=%v)", code, err, redirectHit.Load())
		}
	}

	// Truncates large 500 error responses, rejects malformed JSON and >4 MiB responses.
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		wantSub string
	}{
		{"truncated 500", http.StatusInternalServerError, strings.Repeat("X", 4096), "... [truncated]"},
		{"malformed JSON", http.StatusOK, "{not-json", "unmarshal sandbox response"},
		{"oversized 200", http.StatusOK, strings.Repeat("A", maxSandboxResponseBytes+10), "exceeds maximum size"},
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(tc.status)
			_, _ = w.Write([]byte(tc.body))
		}))
		t.Cleanup(srv.Close)
		_, err := (&HTTPSignatureGenerator{SandboxURL: srv.URL}).GenerateBatch(context.Background(), []*osvschema.Vulnerability{testVuln("OSV-ERR")}, "")
		if err == nil || !strings.Contains(err.Error(), tc.wantSub) {
			t.Errorf("%s: got err=%v, want substring %q", tc.name, err, tc.wantSub)
		}
	}
}
