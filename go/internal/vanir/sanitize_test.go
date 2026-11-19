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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/gitter"
	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	validCommit1 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	validCommit2 = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestSanitizeForVanir_BlocksAndroidSmuggling(t *testing.T) {
	ecoSpec, err := structpb.NewStruct(map[string]any{
		"fixes": []any{"--upload-pack=sh -c pwn@main"},
	})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}

	orig := &osvschema.Vulnerability{
		Id:         "GHSA-1234-5678-9012",
		Summary:    "Secret summary",
		Details:    "Untrusted details",
		References: []*osvschema.Reference{{Type: osvschema.Reference_ADVISORY, Url: "https://example.com"}},
		Credits:    []*osvschema.Credit{{Name: "researcher"}},
		Affected: []*osvschema.Affected{
			{
				Package:           &osvschema.Package{Ecosystem: "Android", Name: "platform/frameworks/base"},
				EcosystemSpecific: ecoSpec,
			},
			{
				Package:           &osvschema.Package{Ecosystem: "Pixel:14", Name: "modem"},
				EcosystemSpecific: ecoSpec,
			},
			{
				Package: &osvschema.Package{Ecosystem: "PyPI", Name: "foo"},
				EcosystemSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"fixes": structpb.NewListValue(&structpb.ListValue{
							Values: []*structpb.Value{structpb.NewStringValue("https://evil.example/fix")},
						}),
					},
				},
				Ranges: []*osvschema.Range{
					{
						Type:   osvschema.Range_GIT,
						Repo:   "https://github.com/example/foo",
						Events: []*osvschema.Event{{Fixed: validCommit1}},
					},
				},
			},
		},
	}

	sanitized, targets, needsNetwork, indexMap := sanitizeForVanirWithIndexMap(orig)

	if sanitized.GetSummary() != "" || sanitized.GetDetails() != "" || len(sanitized.GetReferences()) != 0 || len(sanitized.GetCredits()) != 0 {
		t.Errorf("expected Summary/Details/References/Credits to be stripped")
	}
	if orig.GetSummary() != "Secret summary" {
		t.Errorf("orig vulnerability was mutated")
	}
	if needsNetwork {
		t.Errorf("expected needsNetwork=false for GHSA advisory")
	}
	if len(sanitized.GetAffected()) != 1 {
		t.Fatalf("expected Android/Pixel entries to be stripped, got %d affected entries", len(sanitized.GetAffected()))
	}
	if diff := cmp.Diff([]int{2}, indexMap); diff != "" {
		t.Errorf("indexMap mismatch (-want +got):\n%s", diff)
	}
	if _, hasFixes := sanitized.GetAffected()[0].GetEcosystemSpecific().GetFields()["fixes"]; hasFixes {
		t.Errorf("expected ecosystem_specific.fixes to be stripped on non-Android entry")
	}
	wantTargets := map[string][]string{
		"https://github.com/example/foo": {validCommit1},
	}
	if diff := cmp.Diff(wantTargets, targets); diff != "" {
		t.Errorf("gitTargets mismatch (-want +got):\n%s", diff)
	}
}

func TestSanitizeForVanir_CanonicalAndroidAllowsTrustedFixes(t *testing.T) {
	ecoSpec, err := structpb.NewStruct(map[string]any{
		"fixes": []any{
			"https://android.googlesource.com/platform/art/+/deadbeef",
			"https://git.codelinaro.org/clo/la/kernel/msm-5.4/-/commit/abcdef1234567",
			"https://source.codeaurora.org/quic/la/kernel/msm-4.14/commit/?id=1234567890abcdef",
			"https://evil.example.com/platform/art/+/deadbeef",
			"http://android.googlesource.com/platform/art/+/deadbeef",
			"--upload-pack=pwn@main",
			"https://android.googlesource.com/platform/art/+/deadbeef@--upload-pack=pwn",
			"https://android.googlesource.com/platform/art/+/--upload-pack=pwn",
			"https://android.googlesource.com:8443/platform/art/+/deadbeef",
			"https://git.codelinaro.org/other/repo/commit/abcdef1234567",
		},
	})
	if err != nil {
		t.Fatalf("NewStruct: %v", err)
	}

	v := &osvschema.Vulnerability{
		Id: "ASB-A-123456",
		Affected: []*osvschema.Affected{
			{
				Package:           &osvschema.Package{Ecosystem: "Android", Name: "platform/art"},
				EcosystemSpecific: ecoSpec,
			},
		},
	}

	sanitized, targets, needsNetwork := SanitizeForVanir(v)
	if !needsNetwork {
		t.Errorf("expected needsNetwork=true for canonical Android advisory with valid fix URL")
	}
	if len(targets) != 0 {
		t.Errorf("expected no git targets, got %v", targets)
	}
	gotFixes := sanitized.GetAffected()[0].GetEcosystemSpecific().GetFields()["fixes"].GetListValue().GetValues()
	wantFixes := []string{
		"https://android.googlesource.com/platform/art/+/deadbeef",
		"https://git.codelinaro.org/clo/la/kernel/msm-5.4/-/commit/abcdef1234567",
		"https://source.codeaurora.org/quic/la/kernel/msm-4.14/commit/?id=1234567890abcdef",
	}
	gotStrs := make([]string, 0, len(gotFixes))
	for _, f := range gotFixes {
		gotStrs = append(gotStrs, f.GetStringValue())
	}
	if diff := cmp.Diff(wantFixes, gotStrs); diff != "" {
		t.Errorf("filtered Android fixes mismatch (-want +got):\n%s", diff)
	}
}

func TestSanitizeForVanir_RejectsDangerousGitReposAndEvents(t *testing.T) {
	badRepos := []string{
		"--upload-pack=sh -c id",
		"ssh://git@github.com/example/repo.git",
		"file:///etc/passwd",
		"ext::sh -c id",
		"http://169.254.169.254/latest/meta-data/",
		"http://10.0.0.1/internal/repo.git",
		"http://172.16.0.1/repo.git",
		"http://192.168.1.1/repo.git",
		"http://127.0.0.1/repo.git",
		"http://[::1]/repo.git",
		"http://[::ffff:169.254.169.254]/latest",
		"http://localhost/repo.git",
		"http://gitter-service:8888/repo.git",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://redis.default.svc.cluster.local/repo.git",
		"http://2130706433/repo.git",
		"http://0x7f000001/repo.git",
		"http://0177.0.0.1/repo.git",
		"http://127.1/repo.git",
		"https://user:pass@github.com/example/repo.git",
		"https://github.com/example/repo@evil",
		"https://github.com/",
		"git://evil.example.com/repo.git",
	}

	ranges := make([]*osvschema.Range, 0, len(badRepos)+3)
	for _, repo := range badRepos {
		ranges = append(ranges, &osvschema.Range{
			Type:   osvschema.Range_GIT,
			Repo:   repo,
			Events: []*osvschema.Event{{Fixed: validCommit1}},
		})
	}
	// Bad fixed event on good repo should be dropped; uppercase hex normalized to lowercase; query/fragment stripped.
	ranges = append(ranges, &osvschema.Range{
		Type: osvschema.Range_GIT,
		Repo: "https://GitHub.com/example/good-repo?foo=bar#frag",
		Events: []*osvschema.Event{
			{Introduced: "0"},
			{Fixed: "--upload-pack=pwn"},
			{Fixed: "not-a-hex-hash"},
			{Fixed: strings.ToUpper(validCommit2)},
		},
	})
	// git://github.com should normalize to https://github.com.
	ranges = append(ranges, &osvschema.Range{
		Type:   osvschema.Range_GIT,
		Repo:   "git://github.com/example/git-scheme-repo",
		Events: []*osvschema.Event{{Fixed: validCommit1}},
	})

	v := &osvschema.Vulnerability{
		Id: "OSV-2026-100",
		Affected: []*osvschema.Affected{
			{Ranges: ranges},
		},
	}

	sanitized, targets, needsNetwork := SanitizeForVanir(v)
	if needsNetwork {
		t.Errorf("expected needsNetwork=false")
	}

	wantTargets := map[string][]string{
		"https://github.com/example/good-repo":       {validCommit2},
		"https://github.com/example/git-scheme-repo": {validCommit1},
	}
	if diff := cmp.Diff(wantTargets, targets); diff != "" {
		t.Errorf("gitTargets mismatch (-want +got):\n%s", diff)
	}

	gotRanges := sanitized.GetAffected()[0].GetRanges()
	if len(gotRanges) != 2 {
		t.Fatalf("expected 2 valid GIT ranges remaining, got %d", len(gotRanges))
	}
	if len(gotRanges[0].GetEvents()) != 1 || gotRanges[0].GetEvents()[0].GetFixed() != validCommit2 {
		t.Errorf("expected only valid fixed event %s, got %v", validCommit2, gotRanges[0].GetEvents())
	}
	if gotRanges[1].GetRepo() != "https://github.com/example/git-scheme-repo" {
		t.Errorf("expected git://github.com normalized to https://, got %q", gotRanges[1].GetRepo())
	}
}

func TestSanitizeForVanir_CapsCommitsPerRepo(t *testing.T) {
	events := make([]*osvschema.Event, 0, maxCommitsPerRepo+10)
	for i := range maxCommitsPerRepo + 10 {
		events = append(events, &osvschema.Event{
			Fixed: fmt.Sprintf("%040x", i+1),
		})
	}
	v := &osvschema.Vulnerability{
		Id: "OSV-2026-MANY",
		Affected: []*osvschema.Affected{{
			Ranges: []*osvschema.Range{{
				Type:   osvschema.Range_GIT,
				Repo:   "https://github.com/example/many-commits",
				Events: events,
			}},
		}},
	}

	sanitized, targets, _ := SanitizeForVanir(v)
	if got := len(targets["https://github.com/example/many-commits"]); got != maxCommitsPerRepo {
		t.Errorf("gitTargets count = %d, want %d", got, maxCommitsPerRepo)
	}
	if got := len(sanitized.GetAffected()[0].GetRanges()[0].GetEvents()); got != maxCommitsPerRepo {
		t.Errorf("sanitized events count = %d, want %d", got, maxCommitsPerRepo)
	}
}

func TestValidateSignatures(t *testing.T) {
	origVuln := &osvschema.Vulnerability{
		Id: "OSV-2026-42",
		Affected: []*osvschema.Affected{
			{
				Ranges: []*osvschema.Range{{
					Type:   osvschema.Range_GIT,
					Repo:   "https://github.com/example/repo",
					Events: []*osvschema.Event{{Fixed: validCommit1}},
				}},
			},
			{
				Package: &osvschema.Package{Ecosystem: "PyPI", Name: "no-git-here"},
			},
		},
	}

	validFuncSig := func() map[string]any {
		return map[string]any{
			"id":                "OSV-2026-42-1234abcd",
			"signature_type":    "Function",
			"signature_version": "v1",
			"source":            "https://github.com/example/repo/commit/" + validCommit1,
			"target":            map[string]any{"file": "src/main.c", "function": "parse"},
			"digest":            map[string]any{"function_hash": "99887766", "length": float64(15)},
			"deprecated":        false,
		}
	}

	validLineSig := func() map[string]any {
		return map[string]any{
			"id":                "OSV-2026-42-abcd1234",
			"signature_type":    "Line",
			"signature_version": "v1",
			"source":            "https://github.com/example/repo/commit/" + validCommit1,
			"target":            map[string]any{"file": "src/main.c"},
			"digest":            map[string]any{"line_hashes": []any{"111", "222"}, "threshold": float64(0.85)},
			"deprecated":        false,
		}
	}

	t.Run("accepts valid Function and Line signatures", func(t *testing.T) {
		got, err := ValidateSignatures(origVuln, map[string][]any{
			"0": {validFuncSig(), validLineSig()},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got[0]) != 2 {
			t.Fatalf("got %d validated sigs, want 2", len(got[0]))
		}
	})

	t.Run("rejects wrong vuln ID prefix", func(t *testing.T) {
		sig := validFuncSig()
		sig["id"] = "CVE-OTHER-12345678"
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for mismatched vuln ID prefix")
		}
	})

	t.Run("rejects unexpected top-level key", func(t *testing.T) {
		sig := validFuncSig()
		sig["injected_field"] = "pwn"
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for unexpected top-level key")
		}
	})

	t.Run("rejects out-of-bounds affected index", func(t *testing.T) {
		if _, err := ValidateSignatures(origVuln, map[string][]any{"9": {validFuncSig()}}); err == nil {
			t.Fatal("expected error for out-of-bounds affected index")
		}
	})

	t.Run("rejects affected entry without GIT range", func(t *testing.T) {
		if _, err := ValidateSignatures(origVuln, map[string][]any{"1": {validFuncSig()}}); err == nil {
			t.Fatal("expected error for affected index lacking GIT range")
		}
	})

	t.Run("rejects exceeding 256 signatures per affected", func(t *testing.T) {
		many := make([]any, maxSignaturesPerAffected+1)
		for i := range many {
			many[i] = validFuncSig()
		}
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": many}); err == nil {
			t.Fatal("expected error for >256 signatures")
		}
	})

	t.Run("rejects oversized payload >2 MiB", func(t *testing.T) {
		sig := validFuncSig()
		sig["source"] = strings.Repeat("a", maxSignaturesJSONBytes+10)
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for payload exceeding 2 MiB")
		}
	})

	t.Run("rejects invalid signature_type", func(t *testing.T) {
		sig := validFuncSig()
		sig["signature_type"] = "Arbitrary"
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for unsupported signature_type")
		}
	})

	t.Run("rejects Function signature missing target.function", func(t *testing.T) {
		sig := validFuncSig()
		sig["target"] = map[string]any{"file": "src/main.c"}
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for Function signature missing target.function")
		}
	})

	t.Run("rejects Line signature with unexpected target.function", func(t *testing.T) {
		sig := validLineSig()
		sig["target"] = map[string]any{"file": "src/main.c", "function": "parse"}
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for Line signature with target.function")
		}
	})

	t.Run("rejects non-integer digest.length", func(t *testing.T) {
		sig := validFuncSig()
		sig["digest"] = map[string]any{"function_hash": "99887766", "length": float64(15.5)}
		if _, err := ValidateSignatures(origVuln, map[string][]any{"0": {sig}}); err == nil {
			t.Fatal("expected error for fractional digest.length")
		}
	})
}

type mockGitterClient struct {
	gitter.Client

	calls atomic.Int32
	packs map[string][]byte
	errs  map[string]error
}

func (m *mockGitterClient) GetCommitPack(_ context.Context, req *pb.CommitPackRequest) ([]byte, error) {
	m.calls.Add(1)
	if err, ok := m.errs[req.GetUrl()]; ok {
		return nil, err
	}

	return m.packs[req.GetUrl()], nil
}

func TestHTTPSignatureGenerator(t *testing.T) {
	const repoURL = "https://github.com/example/shared-repo"
	const missingRepoURL = "https://github.com/example/deleted-repo"

	var sandboxCalls atomic.Int32
	sandbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/generate" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)

			return
		}
		sandboxCalls.Add(1)

		var req sandboxGenerateRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Errorf("decode request: %v", err)
			w.WriteHeader(http.StatusBadRequest)

			return
		}

		if req.AllowNetwork {
			t.Errorf("expected AllowNetwork=false when all repos are packed")
		}
		if string(req.RepoPacks[repoURL]) != "zst-pack-bytes" {
			t.Errorf("unexpected repo pack bytes: %q", string(req.RepoPacks[repoURL]))
		}

		var vulnObj struct {
			ID string `json:"id"`
		}
		_ = json.Unmarshal(req.Vulnerability, &vulnObj)

		resp := sandboxGenerateResponse{
			Signatures: map[string][]any{
				"0": {
					map[string]any{
						"id":                vulnObj.ID + "-11223344",
						"signature_type":    "Function",
						"signature_version": "v1",
						"source":            repoURL + "/commit/" + validCommit1,
						"target":            map[string]any{"file": "a.c", "function": "f"},
						"digest":            map[string]any{"function_hash": "42", "length": float64(5)},
						"deprecated":        false,
					},
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(sandbox.Close)

	mg := &mockGitterClient{
		packs: map[string][]byte{
			repoURL: []byte("zst-pack-bytes"),
		},
		errs: map[string]error{
			missingRepoURL: gitter.ErrRepoNotFound,
		},
	}

	gen := &HTTPSignatureGenerator{
		SandboxURL:   sandbox.URL,
		HTTPClient:   sandbox.Client(),
		GitterClient: mg,
	}

	// Vuln 1 has a smuggled Android entry at index 0 and a valid GIT entry at index 1.
	// Vuln 2 references the exact same (repoURL, validCommit1) to verify gitter pack caching.
	// Vuln 3 only references a 404 repo, which should be skipped cleanly without error or sandbox call.
	vulns := []*osvschema.Vulnerability{
		{
			Id: "GHSA-aaaa-bbbb-cccc",
			Affected: []*osvschema.Affected{
				{Package: &osvschema.Package{Ecosystem: "Android", Name: "smuggled"}},
				{
					Ranges: []*osvschema.Range{{
						Type:   osvschema.Range_GIT,
						Repo:   repoURL,
						Events: []*osvschema.Event{{Fixed: validCommit1}},
					}},
				},
			},
		},
		{
			Id: "GHSA-dddd-eeee-ffff",
			Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{{
						Type:   osvschema.Range_GIT,
						Repo:   repoURL,
						Events: []*osvschema.Event{{Fixed: validCommit1}},
					}},
				},
			},
		},
		{
			Id: "GHSA-0000-4040-0000",
			Affected: []*osvschema.Affected{
				{
					Ranges: []*osvschema.Range{{
						Type:   osvschema.Range_GIT,
						Repo:   missingRepoURL,
						Events: []*osvschema.Event{{Fixed: validCommit1}},
					}},
				},
			},
		},
	}

	got, err := gen.GenerateBatch(context.Background(), vulns, "")
	if err != nil {
		t.Fatalf("GenerateBatch failed: %v", err)
	}

	// Verify Vuln 1's signature was remapped back to original affected[1] (not affected[0]).
	if len(got["GHSA-aaaa-bbbb-cccc"][1]) != 1 {
		t.Errorf("expected remapped signature at affected[1] for GHSA-aaaa-bbbb-cccc, got %+v", got["GHSA-aaaa-bbbb-cccc"])
	}
	if len(got["GHSA-aaaa-bbbb-cccc"][0]) != 0 {
		t.Errorf("unexpected signature on stripped affected[0]: %+v", got["GHSA-aaaa-bbbb-cccc"][0])
	}

	if len(got["GHSA-dddd-eeee-ffff"][0]) != 1 {
		t.Errorf("expected signature at affected[0] for GHSA-dddd-eeee-ffff, got %+v", got["GHSA-dddd-eeee-ffff"])
	}
	if _, ok := got["GHSA-0000-4040-0000"]; ok {
		t.Errorf("expected 404 repo vuln to produce no signatures")
	}

	// Gitter should have been called twice total: once for repoURL (cached for Vuln 2) and once for missingRepoURL.
	if gotCalls := mg.calls.Load(); gotCalls != 2 {
		t.Errorf("gitter GetCommitPack called %d times, want 2 (1 cached hit)", gotCalls)
	}
	if gotSandboxCalls := sandboxCalls.Load(); gotSandboxCalls != 2 {
		t.Errorf("sandbox called %d times, want 2 (skipping 404 repo)", gotSandboxCalls)
	}
}

type blockingGitterClient struct {
	gitter.Client

	started chan struct{}
	release chan struct{}
	calls   atomic.Int32
}

func (b *blockingGitterClient) GetCommitPack(ctx context.Context, _ *pb.CommitPackRequest) ([]byte, error) {
	if b.calls.Add(1) == 1 {
		close(b.started)
	}
	select {
	case <-b.release:
		return []byte("shared-pack-bytes"), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestHTTPSignatureGenerator_SingleflightCancelIsolation(t *testing.T) {
	bg := &blockingGitterClient{
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	gen := &HTTPSignatureGenerator{
		GitterClient: bg,
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	var wg sync.WaitGroup
	var err1, err2 error
	var pack2 []byte

	wg.Add(2)
	go func() {
		defer wg.Done()
		_, err1 = gen.getCommitPack(ctx1, "https://github.com/example/sf", []string{validCommit1}, "V1")
	}()

	<-bg.started
	go func() {
		defer wg.Done()
		pack2, err2 = gen.getCommitPack(context.Background(), "https://github.com/example/sf", []string{validCommit1}, "V2")
	}()

	// Give goroutine 2 time to join the singleflight group, then cancel caller 1.
	time.Sleep(30 * time.Millisecond)
	cancel1()
	close(bg.release)
	wg.Wait()

	if err1 == nil {
		t.Errorf("expected cancelled caller 1 to return context error, got nil")
	}
	if err2 != nil {
		t.Fatalf("expected caller 2 to succeed despite caller 1 cancellation, got %v", err2)
	}
	if string(pack2) != "shared-pack-bytes" {
		t.Errorf("caller 2 got %q, want shared-pack-bytes", string(pack2))
	}
	if got := bg.calls.Load(); got != 1 {
		t.Errorf("expected 1 underlying gitter call, got %d", got)
	}
}

func TestHTTPSignatureGenerator_SkipsOversizedPack(t *testing.T) {
	mg := &mockGitterClient{
		errs: map[string]error{
			"https://github.com/example/huge-repo": gitter.ErrPackTooLarge,
		},
	}
	gen := &HTTPSignatureGenerator{
		SandboxURL:   "http://127.0.0.1:1", // Should never be called
		GitterClient: mg,
	}
	v := &osvschema.Vulnerability{
		Id: "OSV-2026-HUGE",
		Affected: []*osvschema.Affected{{
			Ranges: []*osvschema.Range{{
				Type:   osvschema.Range_GIT,
				Repo:   "https://github.com/example/huge-repo",
				Events: []*osvschema.Event{{Fixed: validCommit1}},
			}},
		}},
	}
	got, err := gen.GenerateBatch(context.Background(), []*osvschema.Vulnerability{v}, "")
	if err != nil {
		t.Fatalf("expected ErrPackTooLarge repo to be skipped cleanly without error, got %v", err)
	}
	if len(got) != 0 {
		t.Errorf("expected empty result for skipped oversized repo, got %+v", got)
	}
}
