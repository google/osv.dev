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
	"archive/tar"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func runGit(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_AUTHOR_NAME=Test",
		"GIT_AUTHOR_EMAIL=test@example.com",
		"GIT_COMMITTER_NAME=Test",
		"GIT_COMMITTER_EMAIL=test@example.com",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v failed: %v\noutput: %s", args, err, string(out))
	}

	return strings.TrimSpace(string(out))
}

// buildTestCommitPack creates a real standalone shallow bare git repo .tar.zst archive
// and returns the archive bytes and the target fix commit hash.
func buildTestCommitPack(t *testing.T) ([]byte, string) {
	t.Helper()
	tmp := t.TempDir()
	srcDir := filepath.Join(tmp, "src")
	if err := os.MkdirAll(srcDir, 0755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	runGit(t, srcDir, "init", "-q")
	if err := os.WriteFile(filepath.Join(srcDir, "vuln.c"), []byte("int f() { return 0; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c: %v", err)
	}
	runGit(t, srcDir, "add", "vuln.c")
	runGit(t, srcDir, "commit", "-q", "-m", "initial")

	if err := os.WriteFile(filepath.Join(srcDir, "vuln.c"), []byte("int f() { return 1; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c v2: %v", err)
	}
	runGit(t, srcDir, "add", "vuln.c")
	runGit(t, srcDir, "commit", "-q", "-m", "fix")
	fixCommit := runGit(t, srcDir, "rev-parse", "HEAD")

	shallowDir := filepath.Join(tmp, "shallow.git")
	runGit(t, tmp, "--git-dir="+shallowDir, "init", "--bare", "--quiet")
	runGit(t, tmp, "--git-dir="+shallowDir, "remote", "add", "origin", "file://"+srcDir)
	runGit(t, tmp, "--git-dir="+shallowDir, "config", "remote.origin.uploadpack",
		"git -c uploadpack.allowFilter=true -c uploadpack.allowAnySHA1InWant=true upload-pack")
	runGit(t, tmp, "--git-dir="+shallowDir, "fetch", "--quiet", "--filter=blob:none", "--depth=2", "--no-tags", "origin", fixCommit)
	runGit(t, tmp, "--git-dir="+shallowDir, "--no-pager", "format-patch", "--stdout", "-1", fixCommit)
	runGit(t, tmp, "--git-dir="+shallowDir, "config", "--remove-section", "remote.origin")
	runGit(t, tmp, "--git-dir="+shallowDir, "config", "uploadpack.allowFilter", "true")
	runGit(t, tmp, "--git-dir="+shallowDir, "config", "uploadpack.allowAnySHA1InWant", "true")
	_ = os.RemoveAll(filepath.Join(shallowDir, "hooks"))

	archivePath := filepath.Join(tmp, "pack.tar.zst")
	tarCmd := exec.Command("tar", "--zstd", "-cf", archivePath, "-C", shallowDir, ".")
	if out, err := tarCmd.CombinedOutput(); err != nil {
		t.Fatalf("tar --zstd failed: %v\noutput: %s", err, string(out))
	}

	packBytes, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatalf("read archive: %v", err)
	}

	return packBytes, fixCommit
}

func makeZstTar(t *testing.T, entries []struct {
	hdr  tar.Header
	body []byte
}) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	tw := tar.NewWriter(zw)
	for _, e := range entries {
		hdr := e.hdr
		if hdr.Typeflag == tar.TypeReg {
			hdr.Size = int64(len(e.body))
		}
		if err := tw.WriteHeader(&hdr); err != nil {
			t.Fatalf("WriteHeader(%s): %v", hdr.Name, err)
		}
		if len(e.body) > 0 {
			if _, err := tw.Write(e.body); err != nil {
				t.Fatalf("Write(%s): %v", hdr.Name, err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("tar.Close: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("zstd.Close: %v", err)
	}

	return buf.Bytes()
}

func TestSandboxEndToEnd(t *testing.T) {
	t.Setenv("SANDBOX_CANARY_SECRET", "must-not-leak")

	packBytes, fixCommit := buildTestCommitPack(t)
	workRoot := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "bg.pid")

	// Mock generate_signatures.py that verifies --git-instead-ofs wiring, env stripping,
	// runs a real git fetch via insteadOf against the unpacked commit pack, spawns a
	// background child to verify process reaping, and returns a signature + spoofed vuln ID.
	scriptPath := filepath.Join(t.TempDir(), "mock_generate_signatures.py")
	script := `#!/usr/bin/env python3
import argparse, json, os, subprocess, sys

parser = argparse.ArgumentParser()
parser.add_argument('--input', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--git-working-dir', required=True)
parser.add_argument('--git-instead-ofs', default=None)
args = parser.parse_args()

assert 'SANDBOX_CANARY_SECRET' not in os.environ, 'host env leaked'
assert os.environ.get('GIT_ALLOW_PROTOCOL') == 'file', f"bad GIT_ALLOW_PROTOCOL: {os.environ.get('GIT_ALLOW_PROTOCOL')}"
assert args.git_instead_ofs, '--git-instead-ofs missing'

with open(args.input, 'r', encoding='utf-8') as f:
    vulns = json.load(f)
assert len(vulns) == 1
v = vulns[0]
repo_url = v['affected'][0]['ranges'][0]['repo']
fix_rev = v['affected'][0]['ranges'][0]['events'][0]['fixed']

with open(args.git_instead_ofs, 'r', encoding='utf-8') as f:
    instead_ofs = json.load(f)
assert len(instead_ofs) == 1 and instead_ofs[0][0] == repo_url, f"bad instead_ofs: {instead_ofs}"
local_url = instead_ofs[0][1]

# Perform a real git fetch using url.<dest>.insteadOf=<src>, matching Vanir's GitCommit!
work_repo = os.path.join(args.git_working_dir, 'test_repo')
os.makedirs(work_repo, exist_ok=True)
subprocess.run(['git', '--git-dir=' + work_repo, 'init', '--quiet'], check=True)
subprocess.run(['git', '--git-dir=' + work_repo, 'config', '--add', f'url.{local_url}.insteadOf', repo_url], check=True)
subprocess.run(['git', '--git-dir=' + work_repo, 'fetch', '--quiet', '--filter=blob:none', '--no-tags', '--depth=2', repo_url, fix_rev], check=True)
blob = subprocess.run(['git', '--git-dir=' + work_repo, 'show', f'{fix_rev}:vuln.c'], check=True, capture_output=True, text=True).stdout.strip()
assert blob == 'int f() { return 1; }', f'unexpected blob: {blob!r}'

# Spawn a detached background sleeper in the same process group to verify post-request reaping.
bg = subprocess.Popen(
    ['sleep', '60'],
    stdin=subprocess.DEVNULL,
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
)
with open(` + strconv.Quote(pidFile) + `, 'w', encoding='utf-8') as pf:
    pf.write(str(bg.pid))

out = {
    v['id']: {
        '0': [{
            'id': v['id'] + '-deadbeef',
            'signature_type': 'Function',
            'signature_version': 'v1',
            'source': f'{repo_url}/commit/{fix_rev}',
            'target': {'file': 'vuln.c', 'function': 'f'},
            'digest': {'function_hash': '12345', 'length': 10},
            'deprecated': False,
        }]
    },
    'CVE-SPOOFED': {
        '0': [{'id': 'CVE-SPOOFED-11111111'}]
    }
}
with open(args.output, 'w', encoding='utf-8') as f:
    json.dump(out, f)
`
	if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
		t.Fatalf("write mock script: %v", err)
	}

	var shutdownCalled atomic.Bool
	sb := &sandboxServer{
		pythonBin:     "python3",
		scriptPath:    scriptPath,
		baseWorkDir:   workRoot,
		timeout:       30 * time.Second,
		maxRequests:   1,
		useSetuid:     false,
		supportsNetNS: false,
		onMaxRequests: func() { shutdownCalled.Store(true) },
	}

	ts := httptest.NewServer(sb.routes())
	t.Cleanup(ts.Close)

	// 1. Verify /healthz.
	healthResp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET /healthz: %v", err)
	}
	healthResp.Body.Close()
	if healthResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz status = %d, want 200", healthResp.StatusCode)
	}

	// 2. Call POST /v1/generate with the real .tar.zst commit pack.
	const repoURL = "https://github.com/example/vanir-test-repo"
	vulnJSON := json.RawMessage(`{
		"id": "OSV-2026-999",
		"affected": [{
			"ranges": [{
				"type": "GIT",
				"repo": "` + repoURL + `",
				"events": [{"fixed": "` + fixCommit + `"}]
			}]
		}]
	}`)

	reqBody, err := json.Marshal(GenerateRequest{
		Vulnerability: vulnJSON,
		RepoPacks:     map[string][]byte{repoURL: packBytes},
		AllowNetwork:  false,
	})
	if err != nil {
		t.Fatalf("marshal request: %v", err)
	}

	resp, err := http.Post(ts.URL+"/v1/generate", "application/json", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatalf("POST /v1/generate: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("POST /v1/generate status = %d, want 200; body = %s", resp.StatusCode, buf.String())
	}

	var genResp GenerateResponse
	if err := json.NewDecoder(resp.Body).Decode(&genResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	sigs := genResp.Signatures["0"]
	if len(sigs) != 1 {
		t.Fatalf("got %d signatures for affected[0], want 1 (full resp: %+v)", len(sigs), genResp)
	}

	// 3. Verify background survivor process was killed (gone or zombie awaiting init reap).
	pidBytes, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("read pidFile: %v", err)
	}
	bgPID, err := strconv.Atoi(strings.TrimSpace(string(pidBytes)))
	if err != nil {
		t.Fatalf("parse bgPID: %v", err)
	}
	isDeadOrZombie := func(pid int) bool {
		if err := syscall.Kill(pid, 0); err != nil {
			return true
		}
		status, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "status"))
		if err != nil {
			return true
		}

		return strings.Contains(string(status), "\nState:\tZ") || strings.Contains(string(status), "\nState:\tX")
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !isDeadOrZombie(bgPID) {
		time.Sleep(20 * time.Millisecond)
	}
	if !isDeadOrZombie(bgPID) {
		_ = syscall.Kill(bgPID, syscall.SIGKILL)
		t.Errorf("background process %d survived after request completion", bgPID)
	}

	// 4. Verify temporary job & repo directories were cleaned up.
	entries, err := os.ReadDir(workRoot)
	if err != nil {
		t.Fatalf("ReadDir workRoot: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected workRoot to be empty after cleanup, found %d entries", len(entries))
	}

	// 5. Verify maxRequests triggered shutdown callback.
	shutdownDeadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(shutdownDeadline) && !shutdownCalled.Load() {
		time.Sleep(10 * time.Millisecond)
	}
	if !shutdownCalled.Load() {
		t.Errorf("expected onMaxRequests to be triggered after reaching maxRequests=1")
	}
}

func TestExtractTarZstSafely(t *testing.T) {
	t.Run("rejects path traversal", func(t *testing.T) {
		archive := makeZstTar(t, []struct {
			hdr  tar.Header
			body []byte
		}{
			{hdr: tar.Header{Name: "../escape.txt", Typeflag: tar.TypeReg, Mode: 0644}, body: []byte("pwn")},
		})
		var total int64
		var entries int
		err := extractTarZstSafely(archive, t.TempDir(), &total, maxExtractedBytes, &entries, maxTarEntries)
		if err == nil {
			t.Fatal("expected error for path traversal entry, got nil")
		}
	})

	t.Run("rejects symlinks", func(t *testing.T) {
		archive := makeZstTar(t, []struct {
			hdr  tar.Header
			body []byte
		}{
			{hdr: tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}},
		})
		var total int64
		var entries int
		err := extractTarZstSafely(archive, t.TempDir(), &total, maxExtractedBytes, &entries, maxTarEntries)
		if err == nil {
			t.Fatal("expected error for symlink entry, got nil")
		}
	})

	t.Run("rejects hardlinks", func(t *testing.T) {
		archive := makeZstTar(t, []struct {
			hdr  tar.Header
			body []byte
		}{
			{hdr: tar.Header{Name: "hlink", Typeflag: tar.TypeLink, Linkname: "/etc/passwd"}},
		})
		var total int64
		var entries int
		err := extractTarZstSafely(archive, t.TempDir(), &total, maxExtractedBytes, &entries, maxTarEntries)
		if err == nil {
			t.Fatal("expected error for hardlink entry, got nil")
		}
	})

	t.Run("rejects oversized extraction", func(t *testing.T) {
		archive := makeZstTar(t, []struct {
			hdr  tar.Header
			body []byte
		}{
			{hdr: tar.Header{Name: "big.txt", Typeflag: tar.TypeReg, Mode: 0644}, body: bytes.Repeat([]byte("A"), 2048)},
		})
		var total int64
		var entries int
		err := extractTarZstSafely(archive, t.TempDir(), &total, 1024, &entries, maxTarEntries)
		if err == nil {
			t.Fatal("expected error for oversized archive, got nil")
		}
	})

	t.Run("rejects too many tar entries", func(t *testing.T) {
		archive := makeZstTar(t, []struct {
			hdr  tar.Header
			body []byte
		}{
			{hdr: tar.Header{Name: "a.txt", Typeflag: tar.TypeReg, Mode: 0644}, body: []byte("1")},
			{hdr: tar.Header{Name: "b.txt", Typeflag: tar.TypeReg, Mode: 0644}, body: []byte("2")},
			{hdr: tar.Header{Name: "c.txt", Typeflag: tar.TypeReg, Mode: 0644}, body: []byte("3")},
		})
		var total int64
		var entries int
		err := extractTarZstSafely(archive, t.TempDir(), &total, maxExtractedBytes, &entries, 2)
		if err == nil {
			t.Fatal("expected error when tar entry count exceeds limit, got nil")
		}
	})

	t.Run("strips setuid and exec permissions", func(t *testing.T) {
		archive := makeZstTar(t, []struct {
			hdr  tar.Header
			body []byte
		}{
			{hdr: tar.Header{Name: "sub/bin", Typeflag: tar.TypeReg, Mode: 0o4777}, body: []byte("hello")},
		})
		dest := t.TempDir()
		var total int64
		var entries int
		if err := extractTarZstSafely(archive, dest, &total, maxExtractedBytes, &entries, maxTarEntries); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		fi, err := os.Stat(filepath.Join(dest, "sub", "bin"))
		if err != nil {
			t.Fatalf("stat extracted file: %v", err)
		}
		if fi.Mode().Perm() != 0644 || fi.Mode()&os.ModeSetuid != 0 {
			t.Errorf("got mode %v, want 0644 without setuid", fi.Mode())
		}
		dirInfo, err := os.Stat(filepath.Join(dest, "sub"))
		if err != nil {
			t.Fatalf("stat extracted subdir: %v", err)
		}
		if dirInfo.Mode().Perm() != 0755 {
			t.Errorf("got dir mode %v, want 0755", dirInfo.Mode())
		}
	})
}

func TestSandboxRejectsSymlinkAndFIFOOutput(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{
			name: "symlink output",
			body: "os.unlink(args.output); os.symlink('/etc/hostname', args.output)",
		},
		{
			name: "fifo output",
			body: "os.unlink(args.output); os.mkfifo(args.output)",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			scriptPath := filepath.Join(t.TempDir(), "evil_output.py")
			script := `#!/usr/bin/env python3
import argparse, os
parser = argparse.ArgumentParser()
parser.add_argument('--input', required=True)
parser.add_argument('--output', required=True)
parser.add_argument('--git-working-dir', required=True)
parser.add_argument('--git-instead-ofs', default=None)
args = parser.parse_args()
` + tc.body + "\n"
			if err := os.WriteFile(scriptPath, []byte(script), 0600); err != nil {
				t.Fatalf("write script: %v", err)
			}

			sb := &sandboxServer{
				pythonBin:   "python3",
				scriptPath:  scriptPath,
				baseWorkDir: t.TempDir(),
				timeout:     10 * time.Second,
			}
			ts := httptest.NewServer(sb.routes())
			t.Cleanup(ts.Close)

			reqBody, err := json.Marshal(GenerateRequest{
				Vulnerability: json.RawMessage(`{"id":"OSV-2026-EVIL"}`),
			})
			if err != nil {
				t.Fatalf("marshal request: %v", err)
			}
			resp, err := http.Post(ts.URL+"/v1/generate", "application/json", bytes.NewReader(reqBody))
			if err != nil {
				t.Fatalf("POST /v1/generate: %v", err)
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusInternalServerError {
				t.Errorf("got status %d, want 500 for %s", resp.StatusCode, tc.name)
			}
		})
	}
}
