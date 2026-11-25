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
		var req sandboxGenerateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		var v struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(req.Vulnerability, &v)
		w.Header().Set("Content-Type", "application/json")
		if v.ID == "OSV-BAD-IDX" {
			_, _ = w.Write([]byte(`{"signatures":{"99":[{"id":"OSV-BAD-IDX-1"}]}}`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"signatures":{"0":[{"id":"%s-11223344","signature_type":"Function","signature_version":"v1"}]}}`, v.ID)
	}))
	t.Cleanup(sandbox.Close)

	gen := &HTTPSignatureGenerator{SandboxURL: sandbox.URL, HTTPClient: sandbox.Client()}
	got, err := gen.GenerateBatch(context.Background(), []*osvschema.Vulnerability{
		testVuln("GHSA-aaaa-bbbb-cccc"),
		testVuln("OSV-BAD-IDX"),
	}, "")
	if err != nil {
		t.Fatalf("GenerateBatch: %v", err)
	}
	if len(got["GHSA-aaaa-bbbb-cccc"][0]) != 1 || len(got["OSV-BAD-IDX"]) != 0 {
		t.Errorf("unexpected signatures: %+v", got)
	}
}

func TestHTTPSignatureGenerator_Errors(t *testing.T) {
	if _, err := NewHTTPSignatureGenerator(context.Background(), "http://insecure.example.com"); err == nil {
		t.Error("expected error for non-https sandboxURL")
	}

	var redirectHit atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectHit.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(target.Close)
	redir := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	t.Cleanup(redir.Close)

	v := testVuln("OSV-2026-1")
	if _, err := (&HTTPSignatureGenerator{SandboxURL: redir.URL}).GenerateBatch(context.Background(), []*osvschema.Vulnerability{v}, ""); err == nil || redirectHit.Load() {
		t.Fatalf("redirect should be refused (err=%v hit=%v)", err, redirectHit.Load())
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(strings.Repeat("X", 4096)))
	}))
	t.Cleanup(errSrv.Close)
	if _, err := (&HTTPSignatureGenerator{SandboxURL: errSrv.URL}).GenerateBatch(context.Background(), []*osvschema.Vulnerability{v}, ""); err == nil || !strings.Contains(err.Error(), "... [truncated]") {
		t.Errorf("expected truncated 500 error, got %v", err)
	}
}
