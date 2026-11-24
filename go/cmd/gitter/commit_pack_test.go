package main

import (
	"bytes"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/google/osv.dev/go/internal/gitter/pb/repository"
	"google.golang.org/protobuf/encoding/protojson"
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
		t.Fatalf("git %v failed: %v\noutput: %s", args, err, string(out))
	}

	return strings.TrimSpace(string(out))
}

func doCommitPackReq(t *testing.T, reqMsg *pb.CommitPackRequest, asJSON bool) *httptest.ResponseRecorder {
	t.Helper()
	var payload []byte
	var err error
	ct := "application/x-protobuf"
	if asJSON {
		ct = "application/json"
		payload, err = protojson.Marshal(reqMsg)
	} else {
		payload, err = proto.Marshal(reqMsg)
	}
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
	req.Header.Set("Content-Type", ct)
	req.RemoteAddr = "127.0.0.1:12345"
	rr := httptest.NewRecorder()
	commitPackHandler(rr, req)

	return rr
}

func TestCommitPackHandler(t *testing.T) {
	setupTest(t)

	// Create a local source repo with a 2 MiB unrelated blob and a target fix commit.
	srcRepo := filepath.Join(t.TempDir(), "source-repo")
	if err := os.MkdirAll(srcRepo, 0755); err != nil {
		t.Fatalf("mkdir srcRepo: %v", err)
	}
	runTestGit(t, srcRepo, "init", "-q")
	if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int foo() { return 1; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c: %v", err)
	}
	bigBlob := make([]byte, 2<<20)
	_, _ = rand.Read(bigBlob)
	if err := os.WriteFile(filepath.Join(srcRepo, "unrelated.bin"), bigBlob, 0600); err != nil {
		t.Fatalf("write unrelated.bin: %v", err)
	}
	runTestGit(t, srcRepo, "add", ".")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "initial")

	if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int foo() { return 42; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c v2: %v", err)
	}
	runTestGit(t, srcRepo, "add", "vuln.c")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "fix vuln")
	fixCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

	runTestGit(t, srcRepo, "tag", "-a", "v1.0", "-m", "annotated tag")
	tagObjHash := runTestGit(t, srcRepo, "rev-parse", "v1.0")
	repoURL := "file://" + srcRepo

	t.Run("rejects invalid commits", func(t *testing.T) {
		tooMany := make([]string, maxCommitPackCommits+1)
		for i := range tooMany {
			tooMany[i] = fixCommit
		}
		for _, commits := range [][]string{
			nil,
			{"--upload-pack=touch /tmp/pwn"},
			{"deadbeef"},
			{strings.ToUpper(fixCommit)},
			{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
			tooMany,
		} {
			rr := doCommitPackReq(t, &pb.CommitPackRequest{Url: repoURL, Commits: commits}, true)
			if rr.Code != http.StatusBadRequest {
				t.Errorf("commits=%v: got %d, want 400", commits, rr.Code)
			}
		}
	})

	t.Run("404 on missing commit and annotated tag object", func(t *testing.T) {
		for _, hash := range []string{"0000000000000000000000000000000000000000", tagObjHash} {
			if rr := doCommitPackReq(t, &pb.CommitPackRequest{Url: repoURL, Commits: []string{hash}}, false); rr.Code != http.StatusNotFound {
				t.Errorf("hash=%s: got %d, want 404", hash, rr.Code)
			}
		}
	})

	t.Run("refreshes on new commit after cooldown and supports partial packs", func(t *testing.T) {
		if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int foo() { return 99; }\n"), 0600); err != nil {
			t.Fatalf("write vuln.c v3: %v", err)
		}
		runTestGit(t, srcRepo, "add", "vuln.c")
		runTestGit(t, srcRepo, "commit", "-q", "-m", "new fix")
		newCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

		// Backdate lastFetch beyond cooldown so handler triggers ForceUpdate.
		lastFetchMu.Lock()
		lastFetch[repoURL] = time.Now().Add(-2 * commitPackForceUpdateCooldown)
		lastFetchMu.Unlock()

		rr := doCommitPackReq(t, &pb.CommitPackRequest{
			Url:     repoURL,
			Commits: []string{newCommit, "0000000000000000000000000000000000000000"},
		}, false)
		if rr.Code != http.StatusOK {
			t.Fatalf("got %d, want 200 (body: %s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("standalone pack works after deleting source repo and excludes unrelated blob", func(t *testing.T) {
		rr := doCommitPackReq(t, &pb.CommitPackRequest{
			Url:     repoURL,
			Commits: []string{fixCommit, fixCommit},
			RefId:   "OSV-2026-1",
		}, false)
		if rr.Code != http.StatusOK || rr.Header().Get("Content-Type") != "application/zstd" {
			t.Fatalf("status=%d ct=%q body=%s", rr.Code, rr.Header().Get("Content-Type"), rr.Body.String())
		}
		if rr.Body.Len() > 256*1024 {
			t.Errorf("pack unexpectedly large (%d bytes); unrelated 2 MiB blob may be included", rr.Body.Len())
		}

		tmp := t.TempDir()
		archivePath := filepath.Join(tmp, "pack.tar.zst")
		extractDir := filepath.Join(tmp, "unpacked.git")
		_ = os.MkdirAll(extractDir, 0755)
		if err := os.WriteFile(archivePath, rr.Body.Bytes(), 0600); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		if out, err := exec.Command("tar", "--zstd", "-xf", archivePath, "-C", extractDir).CombinedOutput(); err != nil {
			t.Fatalf("tar extract: %v\n%s", err, out)
		}

		// Delete both source repo and cached clone to prove standalone operation.
		_ = os.RemoveAll(srcRepo)
		_ = os.RemoveAll(gitStorePath)

		vanirWork := filepath.Join(tmp, "vanir-work")
		_ = os.MkdirAll(vanirWork, 0755)
		runTestGit(t, vanirWork, "init", "-q")
		runTestGit(t, vanirWork, "fetch", "--quiet", "--filter=blob:none", "--depth=2", "--no-tags", "file://"+extractDir, fixCommit)
		if got := runTestGit(t, vanirWork, "show", fixCommit+"^:vuln.c"); got != "int foo() { return 1; }" {
			t.Errorf("parent blob = %q", got)
		}
		if got := runTestGit(t, vanirWork, "show", fixCommit+":vuln.c"); got != "int foo() { return 42; }" {
			t.Errorf("fixed blob = %q", got)
		}
	})
}
