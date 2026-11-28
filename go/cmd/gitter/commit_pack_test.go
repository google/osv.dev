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
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"google.golang.org/protobuf/proto"
)

func runTestGit(t *testing.T, dir string, args ...string) string {
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
		t.Fatalf("git %v failed: %v\n%s", args, err, out)
	}

	return strings.TrimSpace(string(out))
}

func postCommitPack(t *testing.T, reqMsg *pb.CommitPackRequest, remoteAddr string) *httptest.ResponseRecorder {
	t.Helper()
	payload, err := proto.Marshal(reqMsg)
	if err != nil {
		t.Fatalf("proto.Marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/x-protobuf")
	req.RemoteAddr = remoteAddr
	rr := httptest.NewRecorder()
	commitPackHandler(rr, req)

	return rr
}

type commitPackFixture struct {
	srcRepo     string
	repoURL     string
	rootCommit  string
	fixCommit   string
	mergeCommit string
	tagOID      string
}

func setupCommitPackFixture(t *testing.T) commitPackFixture {
	t.Helper()
	setupTest(t)

	srcRepo := filepath.Join(t.TempDir(), "src-repo")
	if err := os.MkdirAll(srcRepo, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	runTestGit(t, srcRepo, "init", "-q", "-b", "main")

	// Commit 1 (root): initial vulnerable file + unrelated 2 MiB incompressible blob.
	bigBlob := make([]byte, 2*1024*1024)
	if _, err := rand.Read(bigBlob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRepo, "big.bin"), bigBlob, 0600); err != nil {
		t.Fatalf("write big.bin: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int f() { return 0; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c: %v", err)
	}
	runTestGit(t, srcRepo, "add", ".")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "initial")
	rootCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

	// Commit 2: normal fix touching only vuln.c.
	if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int f() { return 1; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c: %v", err)
	}
	runTestGit(t, srcRepo, "add", "vuln.c")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "fix vuln")
	fixCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")
	runTestGit(t, srcRepo, "tag", "-a", "v1.0", "-m", "annotated tag")
	tagOID := runTestGit(t, srcRepo, "rev-parse", "v1.0")

	// Commit 3 (merge): feature branch modifies merged.c and merges with --no-ff.
	runTestGit(t, srcRepo, "checkout", "-q", "-b", "feat")
	if err := os.WriteFile(filepath.Join(srcRepo, "merged.c"), []byte("int m() { return 42; }\n"), 0600); err != nil {
		t.Fatalf("write merged.c: %v", err)
	}
	runTestGit(t, srcRepo, "add", "merged.c")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "feat change")
	runTestGit(t, srcRepo, "checkout", "-q", "main")
	if err := os.WriteFile(filepath.Join(srcRepo, "other.txt"), []byte("main side\n"), 0600); err != nil {
		t.Fatalf("write other.txt: %v", err)
	}
	runTestGit(t, srcRepo, "add", "other.txt")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "main diverge")
	runTestGit(t, srcRepo, "merge", "-q", "--no-ff", "feat", "-m", "merge feat")
	mergeCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

	return commitPackFixture{
		srcRepo:     srcRepo,
		repoURL:     "file://" + srcRepo,
		rootCommit:  rootCommit,
		fixCommit:   fixCommit,
		mergeCommit: mergeCommit,
		tagOID:      tagOID,
	}
}

func unpackCommitPack(t *testing.T, archive []byte) string {
	t.Helper()
	tmp := t.TempDir()
	archivePath := filepath.Join(tmp, "pack.tar.zst")
	if err := os.WriteFile(archivePath, archive, 0600); err != nil {
		t.Fatalf("write archive: %v", err)
	}
	unpackedDir := filepath.Join(tmp, "unpacked.git")
	if err := os.MkdirAll(unpackedDir, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if out, err := exec.Command("tar", "--zstd", "-xf", archivePath, "-C", unpackedDir).CombinedOutput(); err != nil {
		t.Fatalf("tar --zstd -xf failed: %v\n%s", err, out)
	}

	return unpackedDir
}

func TestCommitPackHandler(t *testing.T) {
	const localAddr = "127.0.0.1:12345"

	t.Run("validation errors and oversized request", func(t *testing.T) {
		f := setupCommitPackFixture(t)
		tooMany := make([]string, maxCommitPackCommits+1)
		for i := range tooMany {
			tooMany[i] = f.fixCommit
		}
		for _, tc := range []struct {
			name    string
			url     string
			commits []string
			remote  string
		}{
			{"empty commits", f.repoURL, nil, localAddr},
			{"too many commits", f.repoURL, tooMany, localAddr},
			{"short hash", f.repoURL, []string{"deadbeef"}, localAddr},
			{"option injection", f.repoURL, []string{"--upload-pack=pwn"}, localAddr},
			{"non-loopback file url", f.repoURL, []string{f.fixCommit}, "203.0.113.10:443"},
		} {
			rr := postCommitPack(t, &pb.CommitPackRequest{Url: tc.url, Commits: tc.commits}, tc.remote)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("%s: got status %d, want 400 (body=%q)", tc.name, rr.Code, rr.Body.String())
			}
		}

		// Malformed JSON -> 400.
		badReq := httptest.NewRequest(http.MethodPost, "/commit-pack", strings.NewReader("{bad json"))
		badReq.Header.Set("Content-Type", "application/json")
		badReq.RemoteAddr = localAddr
		badRR := httptest.NewRecorder()
		commitPackHandler(badRR, badReq)
		if badRR.Code != http.StatusBadRequest {
			t.Errorf("malformed json: got %d, want 400", badRR.Code)
		}

		// Oversized request body -> 413.
		bigReq := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(bytes.Repeat([]byte("A"), maxCommitPackRequestBytes+10)))
		bigReq.RemoteAddr = localAddr
		bigRR := httptest.NewRecorder()
		commitPackHandler(bigRR, bigReq)
		if bigRR.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("oversized body: got %d, want 413", bigRR.Code)
		}
	})

	t.Run("missing commit, annotated tag, and invalidRepoCache handling", func(t *testing.T) {
		f := setupCommitPackFixture(t)

		rr := postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{"deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"},
		}, localAddr)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("missing commit: got %d, want 404", rr.Code)
		}

		rr = postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.tagOID},
		}, localAddr)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("annotated tag: got %d, want 404", rr.Code)
		}

		// Tagless repo cached as 204 by /tags must NOT block /commit-pack.
		invalidRepoCache.SetWithTTL(f.repoURL, http.StatusNoContent, 1, time.Minute)
		invalidRepoCache.Wait()
		rr = postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.fixCommit},
		}, localAddr)
		if rr.Code != http.StatusOK {
			t.Fatalf("204 cached repo: got %d, want 200 (body=%q)", rr.Code, rr.Body.String())
		}

		// Genuine 404 in invalidRepoCache must short-circuit with 404.
		invalidRepoCache.SetWithTTL(f.repoURL, http.StatusNotFound, 1, time.Minute)
		invalidRepoCache.Wait()
		rr = postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.fixCommit},
		}, localAddr)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("404 cached repo: got %d, want 404", rr.Code)
		}
	})

	t.Run("cooldown suppresses ForceUpdate, then refreshes and builds partial pack", func(t *testing.T) {
		f := setupCommitPackFixture(t)

		// Prime cached clone first.
		if rr := postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.fixCommit},
		}, localAddr); rr.Code != http.StatusOK {
			t.Fatalf("prime cache: got %d", rr.Code)
		}

		// Add a new commit upstream after cache is warm.
		if err := os.WriteFile(filepath.Join(f.srcRepo, "vuln.c"), []byte("int f() { return 2; }\n"), 0600); err != nil {
			t.Fatalf("write vuln.c: %v", err)
		}
		runTestGit(t, f.srcRepo, "add", "vuln.c")
		runTestGit(t, f.srcRepo, "commit", "-q", "-m", "second fix")
		newCommit := runTestGit(t, f.srcRepo, "rev-parse", "HEAD")

		// Within cooldown -> ForceUpdate suppressed -> 404.
		rr := postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{newCommit},
		}, localAddr)
		if rr.Code != http.StatusNotFound {
			t.Fatalf("within cooldown: got %d, want 404", rr.Code)
		}

		// Age lastFetch past cooldown -> ForceUpdate fetches newCommit and builds partial pack.
		lastFetchMu.Lock()
		lastFetch[f.repoURL] = time.Now().Add(-2 * commitPackForceUpdateCooldown)
		lastFetchMu.Unlock()

		rr = postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{newCommit, "0000000000000000000000000000000000000000"},
		}, localAddr)
		if rr.Code != http.StatusOK {
			t.Fatalf("after cooldown partial pack: got %d (body=%q)", rr.Code, rr.Body.String())
		}

		unpacked := unpackCommitPack(t, rr.Body.Bytes())
		if got := runTestGit(t, unpacked, "--git-dir="+unpacked, "show", newCommit+":vuln.c"); got != "int f() { return 2; }" {
			t.Errorf("newCommit:vuln.c = %q, want updated content", got)
		}
	})

	t.Run("standalone pack supports normal, merge, and root commits while excluding unrelated blobs", func(t *testing.T) {
		f := setupCommitPackFixture(t)

		rr := postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.fixCommit, f.mergeCommit, f.fixCommit}, // Distinct commits + dedup
			RefId:   "OSV-2026-1",
		}, localAddr)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, want 200 (body=%q)", rr.Code, rr.Body.String())
		}
		packBytes := rr.Body.Bytes()
		if gotCL := rr.Header().Get("Content-Length"); gotCL != strconv.Itoa(len(packBytes)) {
			t.Errorf("Content-Length = %q, want %d", gotCL, len(packBytes))
		}
		// Unrelated 2 MiB incompressible big.bin must NOT be included.
		if len(packBytes) >= 200*1024 {
			t.Errorf("commit pack unexpectedly large (%d bytes); unrelated 2 MiB blob leaked", len(packBytes))
		}

		// Also verify a standalone root commit pack.
		rootRR := postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.rootCommit},
		}, localAddr)
		if rootRR.Code != http.StatusOK {
			t.Fatalf("root commit pack: got %d (body=%q)", rootRR.Code, rootRR.Body.String())
		}

		// Delete both source repo and gitter store to prove packs are 100% standalone.
		if err := os.RemoveAll(f.srcRepo); err != nil {
			t.Fatalf("RemoveAll srcRepo: %v", err)
		}
		if err := os.RemoveAll(gitStorePath); err != nil {
			t.Fatalf("RemoveAll gitStorePath: %v", err)
		}

		unpacked := unpackCommitPack(t, packBytes)

		// Verify hooks and FETCH_HEAD were stripped and remote.origin detached.
		for _, forbidden := range []string{"hooks", "FETCH_HEAD"} {
			if _, err := os.Stat(filepath.Join(unpacked, forbidden)); !os.IsNotExist(err) {
				t.Errorf("expected %s to be absent from pack", forbidden)
			}
		}
		cfgBytes, err := os.ReadFile(filepath.Join(unpacked, "config"))
		if err != nil {
			t.Fatalf("read config: %v", err)
		}
		if strings.Contains(string(cfgBytes), `remote "origin"`) {
			t.Errorf("expected remote.origin removed from pack config:\n%s", cfgBytes)
		}

		// Simulate offline Vanir fetch from unpacked pack for both normal and merge commits.
		clientRepo := filepath.Join(t.TempDir(), "client.git")
		if err := os.MkdirAll(clientRepo, 0755); err != nil {
			t.Fatalf("MkdirAll clientRepo: %v", err)
		}
		runTestGit(t, clientRepo, "--git-dir="+clientRepo, "init", "--quiet")
		runTestGit(t, clientRepo, "--git-dir="+clientRepo, "fetch", "--quiet", "--filter=blob:none", "--no-tags", "--depth=2", "file://"+unpacked, f.fixCommit, f.mergeCommit)

		if got := runTestGit(t, clientRepo, "--git-dir="+clientRepo, "show", f.fixCommit+":vuln.c"); got != "int f() { return 1; }" {
			t.Errorf("fixCommit:vuln.c = %q", got)
		}
		if got := runTestGit(t, clientRepo, "--git-dir="+clientRepo, "show", f.fixCommit+"^:vuln.c"); got != "int f() { return 0; }" {
			t.Errorf("fixCommit^:vuln.c = %q", got)
		}
		if got := runTestGit(t, clientRepo, "--git-dir="+clientRepo, "show", f.mergeCommit+":merged.c"); got != "int m() { return 42; }" {
			t.Errorf("mergeCommit:merged.c = %q", got)
		}

		// Verify root commit pack has vuln.c offline.
		rootUnpacked := unpackCommitPack(t, rootRR.Body.Bytes())
		if got := runTestGit(t, rootUnpacked, "--git-dir="+rootUnpacked, "show", f.rootCommit+":vuln.c"); got != "int f() { return 0; }" {
			t.Errorf("rootCommit:vuln.c = %q", got)
		}
	})

	t.Run("oversized archive returns 413", func(t *testing.T) {
		f := setupCommitPackFixture(t)
		orig := maxCommitPackArchiveBytes
		maxCommitPackArchiveBytes = 64
		t.Cleanup(func() { maxCommitPackArchiveBytes = orig })

		rr := postCommitPack(t, &pb.CommitPackRequest{
			Url:     f.repoURL,
			Commits: []string{f.fixCommit},
		}, localAddr)
		if rr.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("oversized archive: got %d, want 413 (body=%q)", rr.Code, rr.Body.String())
		}
	})
}
