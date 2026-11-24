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

func TestSandboxEndToEnd(t *testing.T) {
	t.Setenv("SANDBOX_CANARY_SECRET", "must-not-leak")

	workRoot := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "bg.pid")

	scriptPath := filepath.Join(t.TempDir(), "mock_vanir.py")
	script := `#!/usr/bin/env python3
import argparse, json, os, subprocess
p = argparse.ArgumentParser()
p.add_argument('--input', required=True)
p.add_argument('--output', required=True)
p.add_argument('--git-working-dir', required=True)
args = p.parse_args()

assert 'SANDBOX_CANARY_SECRET' not in os.environ
assert os.environ.get('GIT_ALLOW_PROTOCOL') == 'https:http'

v = json.load(open(args.input, encoding='utf-8'))[0]
bg = subprocess.Popen(['sleep', '60'], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
open(` + strconv.Quote(pidFile) + `, 'w', encoding='utf-8').write(str(bg.pid))

json.dump({
    v['id']: {'0': [{'id': v['id'] + '-deadbeef', 'signature_type': 'Function', 'signature_version': 'v1'}]},
    'CVE-SPOOFED': {'0': [{'id': 'CVE-SPOOFED-11111111'}]},
}, open(args.output, 'w', encoding='utf-8'))
`
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		t.Fatalf("write script: %v", err)
	}

	sb := &sandboxServer{
		pythonBin:   "python3",
		scriptPath:  scriptPath,
		baseWorkDir: workRoot,
		timeout:     30 * time.Second,
	}
	ts := httptest.NewServer(sb.routes())
	t.Cleanup(ts.Close)

	if resp, err := http.Get(ts.URL + "/healthz"); err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz failed: %v", err)
	} else {
		resp.Body.Close()
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
	pidBytes, _ := os.ReadFile(pidFile)
	bgPID, _ := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
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

func TestSandboxBusyReturns503(t *testing.T) {
	sb := &sandboxServer{baseWorkDir: t.TempDir()}
	sb.execMu.Lock()
	defer sb.execMu.Unlock()

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/v1/generate", strings.NewReader(`{"vulnerability":{"id":"OSV-BUSY"}}`))
	sb.routes().ServeHTTP(rr, req)
	if rr.Code != http.StatusServiceUnavailable {
		t.Errorf("got %d, want 503", rr.Code)
	}
}
