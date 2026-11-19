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

func TestCommitPackHandler(t *testing.T) {
	setupTest(t)

	// Create a local source git repository with multiple commits and a large unrelated blob.
	srcRepo := filepath.Join(t.TempDir(), "source-repo")
	if err := os.MkdirAll(srcRepo, 0755); err != nil {
		t.Fatalf("mkdir srcRepo: %v", err)
	}
	runTestGit(t, srcRepo, "init", "-q")

	// Commit 1: add a small source file and a 2 MiB incompressible unrelated blob.
	if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int foo() { return 1; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c: %v", err)
	}
	bigBlob := make([]byte, 2<<20)
	if _, err := rand.Read(bigBlob); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}
	if err := os.WriteFile(filepath.Join(srcRepo, "unrelated.bin"), bigBlob, 0600); err != nil {
		t.Fatalf("write unrelated.bin: %v", err)
	}
	runTestGit(t, srcRepo, "add", ".")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "initial commit")
	rootCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

	// Commit 2: fix vuln.c (does not touch unrelated.bin).
	if err := os.WriteFile(filepath.Join(srcRepo, "vuln.c"), []byte("int foo() { return 42; }\n"), 0600); err != nil {
		t.Fatalf("write vuln.c v2: %v", err)
	}
	runTestGit(t, srcRepo, "add", "vuln.c")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "fix vuln")
	fixCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

	// Create an annotated tag pointing to fixCommit (tag object hash must not pass as commit).
	runTestGit(t, srcRepo, "tag", "-a", "v1.0", "-m", "release v1.0", fixCommit)
	tagObjHash := runTestGit(t, srcRepo, "rev-parse", "v1.0")

	// Commit 3: unrelated follow-up commit so fixCommit is not HEAD.
	if err := os.WriteFile(filepath.Join(srcRepo, "README.md"), []byte("readme\n"), 0600); err != nil {
		t.Fatalf("write README.md: %v", err)
	}
	runTestGit(t, srcRepo, "add", "README.md")
	runTestGit(t, srcRepo, "commit", "-q", "-m", "docs")
	docsCommit := runTestGit(t, srcRepo, "rev-parse", "HEAD")

	repoURL := "file://" + srcRepo

	t.Run("rejects invalid and option-injected commits", func(t *testing.T) {
		tooMany := make([]string, maxCommitPackCommits+1)
		for i := range tooMany {
			tooMany[i] = fixCommit
		}

		invalidCases := []struct {
			name    string
			commits []string
		}{
			{name: "empty commits", commits: nil},
			{name: "option injection", commits: []string{"--upload-pack=touch /tmp/pwn"}},
			{name: "short hash", commits: []string{"deadbeef"}},
			{name: "uppercase hex", commits: []string{strings.ToUpper(fixCommit)}},
			{name: "non-hex chars", commits: []string{"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"}},
			{name: "too many commits", commits: tooMany},
		}

		for _, tc := range invalidCases {
			t.Run(tc.name, func(t *testing.T) {
				payload, err := protojson.Marshal(&pb.CommitPackRequest{
					Url:     repoURL,
					Commits: tc.commits,
				})
				if err != nil {
					t.Fatalf("marshal: %v", err)
				}
				req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
				req.Header.Set("Content-Type", "application/json")
				req.RemoteAddr = "127.0.0.1:12345"

				rr := httptest.NewRecorder()
				commitPackHandler(rr, req)
				if rr.Code != http.StatusBadRequest {
					t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusBadRequest, rr.Body.String())
				}
			})
		}
	})

	t.Run("returns 404 for missing commit", func(t *testing.T) {
		payload, err := proto.Marshal(&pb.CommitPackRequest{
			Url:     repoURL,
			Commits: []string{"0000000000000000000000000000000000000000"},
			RefId:   "TEST-MISSING",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.RemoteAddr = "127.0.0.1:12345"

		rr := httptest.NewRecorder()
		commitPackHandler(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("got status %d, want %d (body: %s)", rr.Code, http.StatusNotFound, rr.Body.String())
		}
	})

	t.Run("rejects annotated tag object hash as non-commit", func(t *testing.T) {
		payload, err := proto.Marshal(&pb.CommitPackRequest{
			Url:     repoURL,
			Commits: []string{tagObjHash},
			RefId:   "TEST-TAG",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.RemoteAddr = "127.0.0.1:12345"

		rr := httptest.NewRecorder()
		commitPackHandler(rr, req)
		if rr.Code != http.StatusNotFound {
			t.Errorf("got status %d, want %d for tag object hash (body: %s)", rr.Code, http.StatusNotFound, rr.Body.String())
		}
	})

	t.Run("handles root commit and multiple commits in one pack", func(t *testing.T) {
		payload, err := proto.Marshal(&pb.CommitPackRequest{
			Url:     repoURL,
			Commits: []string{rootCommit, fixCommit, docsCommit},
			RefId:   "TEST-MULTI",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.RemoteAddr = "127.0.0.1:12345"

		rr := httptest.NewRecorder()
		commitPackHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("got status %d, want 200 (body: %s)", rr.Code, rr.Body.String())
		}
	})

	t.Run("creates standalone shallow pack excluding unrelated blobs", func(t *testing.T) {
		payload, err := proto.Marshal(&pb.CommitPackRequest{
			Url:     repoURL,
			Commits: []string{fixCommit, fixCommit}, // Duplicate commit should be deduplicated cleanly
			RefId:   "OSV-2026-1",
		})
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/commit-pack", bytes.NewReader(payload))
		req.Header.Set("Content-Type", "application/x-protobuf")
		req.RemoteAddr = "127.0.0.1:12345"

		rr := httptest.NewRecorder()
		commitPackHandler(rr, req)
		if rr.Code != http.StatusOK {
			t.Fatalf("got status %d, want %d (body: %s)", rr.Code, http.StatusOK, rr.Body.String())
		}
		if ct := rr.Header().Get("Content-Type"); ct != "application/zstd" {
			t.Errorf("Content-Type = %q, want application/zstd", ct)
		}

		packBytes := rr.Body.Bytes()
		// Must be dramatically smaller than the 2 MiB unrelated blob.
		if len(packBytes) > 256*1024 {
			t.Errorf("pack archive unexpectedly large (%d bytes); unrelated blob may have been included", len(packBytes))
		}

		// Extract the .tar.zst pack to a bare repo directory.
		extractDir := filepath.Join(t.TempDir(), "unpacked.git")
		if err := os.MkdirAll(extractDir, 0755); err != nil {
			t.Fatalf("mkdir extractDir: %v", err)
		}
		archivePath := filepath.Join(t.TempDir(), "pack.tar.zst")
		if err := os.WriteFile(archivePath, packBytes, 0600); err != nil {
			t.Fatalf("write archive: %v", err)
		}
		tarCmd := exec.Command("tar", "--zstd", "-xf", archivePath, "-C", extractDir)
		if out, err := tarCmd.CombinedOutput(); err != nil {
			t.Fatalf("tar extract failed: %v\noutput: %s", err, string(out))
		}

		// Delete both the source repo and gitter's cached clone to prove the pack is 100% standalone.
		if err := os.RemoveAll(srcRepo); err != nil {
			t.Fatalf("remove srcRepo: %v", err)
		}
		if err := os.RemoveAll(gitStorePath); err != nil {
			t.Fatalf("remove gitStorePath: %v", err)
		}

		// Simulate Vanir fetching the commit from the standalone pack using --filter=blob:none --depth=2.
		vanirWorkDir := filepath.Join(t.TempDir(), "vanir-work")
		if err := os.MkdirAll(vanirWorkDir, 0755); err != nil {
			t.Fatalf("mkdir vanirWorkDir: %v", err)
		}
		runTestGit(t, vanirWorkDir, "init", "-q")
		runTestGit(t, vanirWorkDir, "fetch", "--quiet", "--filter=blob:none", "--depth=2", "--no-tags", "file://"+extractDir, fixCommit)

		patch := runTestGit(t, vanirWorkDir, "format-patch", "--stdout", "-1", fixCommit)
		if !strings.Contains(patch, "-int foo() { return 1; }") || !strings.Contains(patch, "+int foo() { return 42; }") {
			t.Errorf("unexpected patch from standalone pack:\n%s", patch)
		}
		oldBlob := runTestGit(t, vanirWorkDir, "show", fixCommit+"^:vuln.c")
		if oldBlob != "int foo() { return 1; }" {
			t.Errorf("parent blob = %q, want %q", oldBlob, "int foo() { return 1; }")
		}
		newBlob := runTestGit(t, vanirWorkDir, "show", fixCommit+":vuln.c")
		if newBlob != "int foo() { return 42; }" {
			t.Errorf("fixed blob = %q, want %q", newBlob, "int foo() { return 42; }")
		}
	})
}
