//go:build linux

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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func writeMockScript(t *testing.T, body string) string {
	t.Helper()
	scriptPath := filepath.Join(t.TempDir(), "mock_vanir.py")
	src := "#!/usr/bin/env python3\nimport argparse, json, os, subprocess, sys, time\n" +
		"p = argparse.ArgumentParser()\n" +
		"for a in ('--input', '--output', '--git-working-dir'): p.add_argument(a, required=True)\n" +
		"args = p.parse_args()\n" + body
	if err := os.WriteFile(scriptPath, []byte(src), 0600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	return scriptPath
}

func TestSandboxEndToEnd(t *testing.T) {
	t.Setenv("SANDBOX_CANARY_SECRET", "must-not-leak")

	workRoot := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "bg.pid")

	scriptPath := writeMockScript(t, `
assert 'SANDBOX_CANARY_SECRET' not in os.environ
assert os.environ.get('GIT_ALLOW_PROTOCOL') == 'https:http'

with open(args.input, encoding='utf-8') as f:
    v = json.load(f)[0]
bg = subprocess.Popen(['sleep', '60'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
with open(`+strconv.Quote(pidFile)+`, 'w', encoding='utf-8') as f:
    f.write(str(bg.pid))

with open(args.output, 'w', encoding='utf-8') as f:
    json.dump({
        v['id']: {'0': [{'id': v['id'] + '-deadbeef', 'signature_type': 'Function', 'signature_version': 'v1'}]},
        'CVE-SPOOFED': {'0': [{'id': 'CVE-SPOOFED-11111111'}]},
    }, f)
`)

	sb := &sandboxServer{
		pythonBin:   "python3",
		scriptPath:  scriptPath,
		baseWorkDir: workRoot,
		timeout:     30 * time.Second,
	}
	ts := httptest.NewServer(sb.routes())
	t.Cleanup(ts.Close)

	healthResp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", healthResp.StatusCode)
	}

	reqBody, err := json.Marshal(GenerateRequest{
		Vulnerability: json.RawMessage(`{"id":"OSV-2026-999","affected":[{"ranges":[{"type":"GIT","repo":"https://github.com/example/repo","events":[{"fixed":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}]}]}`),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	resp, err := http.Post(ts.URL+"/v1/generate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /v1/generate: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var b bytes.Buffer
		_, _ = b.ReadFrom(resp.Body)
		t.Fatalf("status=%d body=%s", resp.StatusCode, b.String())
	}

	var genResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if strings.Contains(string(genResp.Signatures), "CVE-SPOOFED") {
		t.Fatalf("spoofed vuln leaked: %s", genResp.Signatures)
	}
	var sigsByIdx map[string][]map[string]any
	if err := json.Unmarshal(genResp.Signatures, &sigsByIdx); err != nil || len(sigsByIdx["0"]) != 1 || sigsByIdx["0"][0]["id"] != "OSV-2026-999-deadbeef" {
		t.Fatalf("unexpected signatures: %s", genResp.Signatures)
	}

	// Verify background process was reaped and temp directories cleaned up.
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pidFile: %v", err)
	}
	bgPID, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil || bgPID <= 0 {
		t.Fatalf("invalid bgPID %q: %v", string(pidBytes), err)
	}
	isDead := func(pid int) bool {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		st, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))

		return err != nil || strings.Contains(string(st), "\nState:\tZ") || strings.Contains(string(st), "\nState:\tX")
	}
	for deadline := time.Now().Add(2 * time.Second); time.Now().Before(deadline) && !isDead(bgPID); {
		time.Sleep(20 * time.Millisecond)
	}
	if !isDead(bgPID) {
		_ = syscall.Kill(bgPID, syscall.SIGKILL)
		t.Errorf("background process %d survived", bgPID)
	}
	if entries, err := os.ReadDir(workRoot); err != nil || len(entries) != 0 {
		t.Errorf("workRoot not empty: %v (%d entries)", err, len(entries))
	}
}

func TestSandboxHTTPGuardsAndErrors(t *testing.T) {
	t.Run("busy and tainted return 503", func(t *testing.T) {
		sb := &sandboxServer{baseWorkDir: t.TempDir()}
		sb.execMu.Lock()
		rr := httptest.NewRecorder()
		sb.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/generate", strings.NewReader(`{"vulnerability":{"id":"OSV-1"}}`)))
		sb.execMu.Unlock()
		if rr.Code != http.StatusServiceUnavailable {
			t.Errorf("busy: got %d, want 503", rr.Code)
		}

		sb.tainted.Store(true)
		for _, tc := range []struct{ method, path string }{
			{http.MethodGet, "/healthz"},
			{http.MethodPost, "/v1/generate"},
		} {
			rr := httptest.NewRecorder()
			sb.routes().ServeHTTP(rr, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{"vulnerability":{"id":"OSV-1"}}`)))
			if rr.Code != http.StatusServiceUnavailable {
				t.Errorf("tainted %s %s: got %d, want 503", tc.method, tc.path, rr.Code)
			}
		}
	})

	t.Run("request validation 400 and 413", func(t *testing.T) {
		sb := &sandboxServer{baseWorkDir: t.TempDir()}
		for _, tc := range []struct {
			name string
			body string
			want int
		}{
			{"invalid json", "{bad", http.StatusBadRequest},
			{"missing vuln id", `{"vulnerability":{}}`, http.StatusBadRequest},
			{"oversized body", `{"vulnerability":{"id":"` + strings.Repeat("a", maxRequestBytes) + `"}}`, http.StatusRequestEntityTooLarge},
		} {
			rr := httptest.NewRecorder()
			sb.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/generate", strings.NewReader(tc.body)))
			if rr.Code != tc.want {
				t.Errorf("%s: got %d, want %d", tc.name, rr.Code, tc.want)
			}
		}
	})

	t.Run("child failure, timeout, empty output, and oversized output", func(t *testing.T) {
		for _, tc := range []struct {
			name     string
			script   string
			timeout  time.Duration
			wantCode int
			wantBody string
		}{
			{"non-zero exit", "sys.stderr.write('boom')\nsys.exit(1)\n", 10 * time.Second, http.StatusInternalServerError, ""},
			{"timeout kills child", "time.sleep(10)\n", 200 * time.Millisecond, http.StatusInternalServerError, ""},
			{"null output falls back to empty object", "open(args.output, 'w').write('{\"OSV-1\": null}')\n", 10 * time.Second, http.StatusOK, `{"signatures":{}}`},
			{"malformed output.json", "open(args.output, 'w').write('{bad')\n", 10 * time.Second, http.StatusInternalServerError, ""},
			{"oversized output.json", "open(args.output, 'w').write('x' * (5 * 1024 * 1024))\n", 10 * time.Second, http.StatusInternalServerError, ""},
		} {
			t.Run(tc.name, func(t *testing.T) {
				workRoot := t.TempDir()
				sb := &sandboxServer{
					pythonBin:   "python3",
					scriptPath:  writeMockScript(t, tc.script),
					baseWorkDir: workRoot,
					timeout:     tc.timeout,
				}
				rr := httptest.NewRecorder()
				sb.routes().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/v1/generate", strings.NewReader(`{"vulnerability":{"id":"OSV-1"}}`)))
				if rr.Code != tc.wantCode {
					t.Errorf("got %d, want %d (body=%q)", rr.Code, tc.wantCode, rr.Body.String())
				}
				if tc.wantBody != "" && strings.TrimSpace(rr.Body.String()) != tc.wantBody {
					t.Errorf("body = %q, want %q", rr.Body.String(), tc.wantBody)
				}
				if entries, err := os.ReadDir(workRoot); err != nil || len(entries) != 0 {
					t.Errorf("workRoot not cleaned up: %v (%d entries)", err, len(entries))
				}
			})
		}
	})
}

func TestCappedBuffer(t *testing.T) {
	b := &cappedBuffer{limit: 5}
	n, err := b.Write([]byte("abcdef"))
	if err != nil || n != 6 {
		t.Fatalf("Write() = (%d, %v), want (6, nil)", n, err)
	}
	if _, err := b.Write([]byte("more")); err != nil {
		t.Fatalf("second Write: %v", err)
	}
	if got := b.String(); got != "abcde... [truncated]" {
		t.Errorf("String() = %q, want %q", got, "abcde... [truncated]")
	}
}
