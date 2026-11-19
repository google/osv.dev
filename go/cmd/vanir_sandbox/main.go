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

// Package main implements the untrusted Mode B Vanir sandbox HTTP server.
// Each request processes a single vulnerability record under a unique Linux UID,
// isolated work directory, read-only unpacked Git commit packs, optional empty
// network namespace, and guaranteed post-request UID process reaping.
package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/klauspost/compress/zstd"
)

const (
	maxRequestBytes    = 64 << 20  // 64 MiB max HTTP request payload
	maxExtractedBytes  = 256 << 20 // 256 MiB max total unpacked repo pack size per request
	maxTarEntries      = 10000     // Max cumulative tar entries unpacked per request (prevents inode exhaustion)
	maxRepoPacks       = 64        // Max repo packs accepted in a single request
	maxZstdWindowBytes = 32 << 20  // 32 MiB max zstd decoder window
	maxZstdMemoryBytes = 64 << 20  // 64 MiB max zstd decoder memory
	maxOutputBytes     = 4 << 20   // 4 MiB max output.json read from untrusted child
	maxChildLogBytes   = 64 << 10  // 64 KiB max stderr/stdout captured from child
	defaultTimeout     = 25 * time.Minute
	shutdownTimeout    = 8 * time.Second // Fits within Cloud Run's 10s SIGTERM grace period
	uidBase            = 10000
	uidSpan            = 50000
	probeUID           = 65534 // nobody
)

// GenerateRequest is the JSON request body for POST /v1/generate.
type GenerateRequest struct {
	Vulnerability json.RawMessage   `json:"vulnerability"` // Single OSV JSON object
	RepoPacks     map[string][]byte `json:"repo_packs"`    // Normalized repoURL -> .tar.zst bytes
	AllowNetwork  bool              `json:"allow_network"` // False when all ranges are covered by RepoPacks
}

// GenerateResponse is the JSON response body for POST /v1/generate.
type GenerateResponse struct {
	Signatures map[string][]any `json:"signatures"` // affected_idx_str -> signature objects
}

// limitedBuffer caps buffered bytes so an untrusted child cannot OOM the supervisor via logs.
type limitedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	origLen := len(p)
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return origLen, nil
	}
	if len(p) > remaining {
		p = p[:remaining]
		b.truncated = true
	}
	_, _ = b.buf.Write(p)

	return origLen, nil
}

func (b *limitedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.truncated {
		return b.buf.String() + "... [truncated]"
	}

	return b.buf.String()
}

type sandboxServer struct {
	pythonBin     string
	scriptPath    string
	baseWorkDir   string
	timeout       time.Duration
	maxRequests   int64
	useSetuid     bool
	supportsNetNS bool
	selfExe       string
	onMaxRequests func()

	execMu       sync.Mutex
	seq          atomic.Int64
	shutdownOnce sync.Once
}

func (s *sandboxServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("POST /v1/generate", s.handleGenerate)

	return mux
}

func (s *sandboxServer) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *sandboxServer) handleGenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Enforce single-request concurrency inside the instance (matches Cloud Run concurrency=1).
	s.execMu.Lock()
	defer s.execMu.Unlock()

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	defer r.Body.Close()

	var req GenerateRequest
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(&req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, fmt.Sprintf("invalid JSON request: %v", err), http.StatusBadRequest)

		return
	}

	vulnID, err := extractVulnID(req.Vulnerability)
	if err != nil {
		http.Error(w, fmt.Sprintf("invalid vulnerability object: %v", err), http.StatusBadRequest)
		return
	}

	n := s.seq.Add(1)
	//nolint:gosec // G115: uidBase + (n % uidSpan) is always in [10000, 59999].
	uid := uint32(uidBase + (n % uidSpan))

	sigs, statusCode, err := s.executeRequest(ctx, n, uid, vulnID, &req)
	if err != nil {
		logger.ErrorContext(ctx, "Sandbox execution failed",
			slog.String("vuln_id", vulnID),
			slog.Int64("seq", n),
			slog.Int("status", statusCode),
			slog.Any("error", err))
		http.Error(w, err.Error(), statusCode)
		s.maybeTriggerShutdown(n)

		return
	}

	resp := GenerateResponse{Signatures: sigs}
	respBytes, err := json.Marshal(resp)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal response: %v", err), http.StatusInternalServerError)
		s.maybeTriggerShutdown(n)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
	_ = http.NewResponseController(w).Flush()

	s.maybeTriggerShutdown(n)
}

func (s *sandboxServer) maybeTriggerShutdown(n int64) {
	if s.maxRequests > 0 && n >= s.maxRequests && s.onMaxRequests != nil {
		s.shutdownOnce.Do(func() {
			go s.onMaxRequests()
		})
	}
}

func hasControlOrWhitespace(s string) bool {
	for i := range len(s) {
		c := s[i]
		if c <= 0x20 || c == 0x7f {
			return true
		}
	}

	return false
}

func (s *sandboxServer) executeRequest(
	ctx context.Context,
	seq int64,
	uid uint32,
	vulnID string,
	req *GenerateRequest,
) (map[string][]any, int, error) {
	if len(req.RepoPacks) > maxRepoPacks {
		return nil, http.StatusBadRequest, fmt.Errorf("too many repo packs (%d > %d)", len(req.RepoPacks), maxRepoPacks)
	}

	reposRoot := filepath.Join(s.baseWorkDir, fmt.Sprintf("vanir-repos-%d", seq))
	jobDir := filepath.Join(s.baseWorkDir, fmt.Sprintf("vanir-job-%d", seq))
	ipcDir := filepath.Join(jobDir, "ipc")
	workDir := filepath.Join(jobDir, "work")
	gitWorkDir := filepath.Join(workDir, "git-work")

	var childPGID int
	var reaped bool
	reapAll := func() {
		if reaped {
			return
		}
		reaped = true
		if childPGID > 0 {
			_ = syscall.Kill(-childPGID, syscall.SIGKILL)
		}
		if s.useSetuid {
			s.reapUID(context.WithoutCancel(ctx), uid)
		}
	}

	defer func() {
		reapAll()
		if s.useSetuid {
			sweepUIDTempFiles(uid, s.baseWorkDir)
		}
		if err := os.RemoveAll(jobDir); err != nil {
			logger.WarnContext(ctx, "Failed to remove jobDir", slog.String("dir", jobDir), slog.Any("error", err))
		}
		if err := os.RemoveAll(reposRoot); err != nil {
			logger.WarnContext(ctx, "Failed to remove reposRoot", slog.String("dir", reposRoot), slog.Any("error", err))
		}
	}()

	if err := os.Mkdir(reposRoot, 0755); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create reposRoot: %w", err)
	}
	if err := os.Chmod(reposRoot, 0755); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to chmod reposRoot: %w", err)
	}

	// Unpack repo packs as UID 0 (0755 dirs, 0644 files) so they are strictly read-only to child UID.
	repoURLs := make([]string, 0, len(req.RepoPacks))
	for repoURL := range req.RepoPacks {
		repoURLs = append(repoURLs, repoURL)
	}
	slices.Sort(repoURLs)

	insteadOfs := make([][2]string, 0, len(repoURLs))
	var totalExtracted int64
	var totalEntries int
	for _, repoURL := range repoURLs {
		if repoURL == "" || hasControlOrWhitespace(repoURL) {
			return nil, http.StatusBadRequest, fmt.Errorf("invalid repo URL key %q", repoURL)
		}
		sum := sha256.Sum256([]byte(repoURL))
		repoDir := filepath.Join(reposRoot, hex.EncodeToString(sum[:])+".git")
		if err := extractTarZstSafely(req.RepoPacks[repoURL], repoDir, &totalExtracted, maxExtractedBytes, &totalEntries, maxTarEntries); err != nil {
			return nil, http.StatusBadRequest, fmt.Errorf("failed to extract repo pack for %s: %w", repoURL, err)
		}
		localFileURL := (&url.URL{Scheme: "file", Path: repoDir}).String()
		insteadOfs = append(insteadOfs, [2]string{repoURL, localFileURL})
	}

	// Keep jobDir and ipcDir owned by root (0:0) so the untrusted child cannot unlink or
	// symlink-swap input.json, instead_ofs.json, or output.json. Only output.json (pre-created)
	// and workDir (HOME/TMPDIR/git-work) are writable by the child UID.
	if err := os.Mkdir(jobDir, 0711); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create jobDir: %w", err)
	}
	if err := os.Chmod(jobDir, 0711); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to chmod jobDir: %w", err)
	}
	if err := os.Mkdir(ipcDir, 0755); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create ipcDir: %w", err)
	}
	if err := os.Chmod(ipcDir, 0755); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to chmod ipcDir: %w", err)
	}
	if err := os.Mkdir(workDir, 0700); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create workDir: %w", err)
	}
	if err := os.Chmod(workDir, 0700); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to chmod workDir: %w", err)
	}
	if err := os.Mkdir(gitWorkDir, 0700); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to create gitWorkDir: %w", err)
	}
	if err := os.Chmod(gitWorkDir, 0700); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to chmod gitWorkDir: %w", err)
	}

	inputPath := filepath.Join(ipcDir, "input.json")
	outputPath := filepath.Join(ipcDir, "output.json")
	insteadOfsPath := filepath.Join(ipcDir, "instead_ofs.json")

	batchPayload, err := json.Marshal([]json.RawMessage{req.Vulnerability})
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to marshal input batch: %w", err)
	}
	if err := os.WriteFile(inputPath, batchPayload, 0600); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to write input.json: %w", err)
	}

	insteadOfsPayload, err := json.Marshal(insteadOfs)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to marshal instead_ofs.json: %w", err)
	}
	if err := os.WriteFile(insteadOfsPath, insteadOfsPayload, 0600); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to write instead_ofs.json: %w", err)
	}

	// Pre-create output.json inside root-owned ipcDir so the child can open/truncate/write it
	// without having directory write permission to unlink or replace it with a symlink.
	outInit, err := os.OpenFile(outputPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to pre-create output.json: %w", err)
	}
	if err := outInit.Close(); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to close pre-created output.json: %w", err)
	}

	if s.useSetuid {
		// Grant read-only group access (0:uid, mode 0640) on input files while keeping root ownership.
		for _, p := range []string{inputPath, insteadOfsPath} {
			if err := os.Chown(p, 0, int(uid)); err != nil {
				return nil, http.StatusInternalServerError, fmt.Errorf("failed to chown %s: %w", p, err)
			}
			if err := os.Chmod(p, 0640); err != nil {
				return nil, http.StatusInternalServerError, fmt.Errorf("failed to chmod %s: %w", p, err)
			}
		}
		for _, p := range []string{workDir, gitWorkDir, outputPath} {
			if err := os.Chown(p, int(uid), int(uid)); err != nil {
				return nil, http.StatusInternalServerError, fmt.Errorf("failed to chown %s: %w", p, err)
			}
		}
	}

	timeout := s.timeout
	if timeout <= 0 {
		timeout = defaultTimeout
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // G204: pythonBin and scriptPath are trusted supervisor config paths.
	cmd := exec.CommandContext(
		cmdCtx,
		s.pythonBin,
		s.scriptPath,
		"--input", inputPath,
		"--output", outputPath,
		"--git-working-dir", gitWorkDir,
		"--git-instead-ofs", insteadOfsPath,
	)

	allowProtocol := "file"
	if req.AllowNetwork {
		allowProtocol = "file:https"
	}

	// Explicitly stripped environment: never inherit os.Environ().
	cmd.Env = []string{
		"PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin",
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"PYTHONDONTWRITEBYTECODE=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		// Allow git-upload-pack under child UID to read 0:0-owned read-only repo packs.
		"GIT_CONFIG_COUNT=1",
		"GIT_CONFIG_KEY_0=safe.directory",
		"GIT_CONFIG_VALUE_0=*",
		"GIT_ALLOW_PROTOCOL=" + allowProtocol,
	}

	sysProcAttr := &syscall.SysProcAttr{
		Setpgid: true,
	}
	if s.useSetuid {
		sysProcAttr.Credential = &syscall.Credential{
			Uid:    uid,
			Gid:    uid,
			Groups: []uint32{},
		}
	}
	if !req.AllowNetwork && s.supportsNetNS {
		sysProcAttr.Cloneflags = syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS
	}
	cmd.SysProcAttr = sysProcAttr
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}

		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	outBuf := &limitedBuffer{limit: maxChildLogBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = outBuf

	if err := cmd.Start(); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to start sandbox child: %w", err)
	}
	childPGID = cmd.Process.Pid

	waitErr := cmd.Wait()
	// Atomically terminate all surviving processes (including double-forked orphans) under uid
	// BEFORE reading output.json so no live untrusted process can race the file read.
	reapAll()

	if waitErr != nil {
		logger.WarnContext(ctx, "Vanir sandbox child failed",
			slog.String("vuln_id", vulnID),
			slog.Int64("seq", seq),
			slog.Any("error", waitErr),
			slog.String("output", outBuf.String()))

		return nil, http.StatusInternalServerError, fmt.Errorf("vanir sandbox execution failed: %w", waitErr)
	}

	// Open output.json atomically with O_NOFOLLOW|O_NONBLOCK and verify via fstat on the open FD
	// to refuse symlinks, FIFOs, or non-regular files with zero TOCTOU window.
	fd, err := syscall.Open(outputPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to open output.json: %w", err)
	}
	f := os.NewFile(uintptr(fd), outputPath)
	defer f.Close()

	fi, err := f.Stat()
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to stat output.json: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, http.StatusInternalServerError, errors.New("output.json is not a regular file")
	}

	outputBytes, err := io.ReadAll(io.LimitReader(f, maxOutputBytes+1))
	if err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to read output.json: %w", err)
	}
	if len(outputBytes) > maxOutputBytes {
		return nil, http.StatusInternalServerError, fmt.Errorf("output.json exceeds max size (%d bytes)", maxOutputBytes)
	}

	var rawOutput map[string]map[string][]any
	if err := json.Unmarshal(outputBytes, &rawOutput); err != nil {
		return nil, http.StatusInternalServerError, fmt.Errorf("failed to unmarshal output.json: %w", err)
	}

	// Pin strictly to the single requested vulnID.
	sigs := rawOutput[vulnID]
	if sigs == nil {
		sigs = map[string][]any{}
	}

	return sigs, http.StatusOK, nil
}

// reapUID spawns a short-lived helper running as the given non-root UID that invokes
// kill(-1, SIGKILL), atomically terminating any double-forked orphan processes under that UID.
func (s *sandboxServer) reapUID(parentCtx context.Context, uid uint32) {
	if uid == 0 || s.selfExe == "" {
		return
	}
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	//nolint:gosec // G204: selfExe is our own binary path resolved at startup.
	cmd := exec.CommandContext(ctx, s.selfExe, "-reap-uid")
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{
			Uid:    uid,
			Gid:    uid,
			Groups: []uint32{},
		},
	}
	err := cmd.Run()
	if err == nil {
		return
	}
	// kill(-1, SIGKILL) kills the helper process itself, so SIGKILL is the expected exit status.
	if exitErr, ok := errors.AsType[*exec.ExitError](err); ok {
		if ws, ok := exitErr.Sys().(syscall.WaitStatus); ok && ws.Signaled() && ws.Signal() == syscall.SIGKILL {
			return
		}
	}
	logger.WarnContext(parentCtx, "Unexpected error from reap-uid helper", slog.Uint64("uid", uint64(uid)), slog.Any("error", err))
}

// sweepUIDTempFiles removes any top-level files or directories in shared world-writable tmpfs
// mounts (/tmp, /dev/shm) owned by uid after all processes for uid have been reaped.
// This cleans up leaked Python forkserver POSIX semaphores and prevents tmpfs exhaustion.
func sweepUIDTempFiles(uid uint32, skipPath string) {
	if uid == 0 {
		return
	}
	cleanSkip := filepath.Clean(skipPath)
	for _, dir := range []string{"/tmp", "/dev/shm"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			p := filepath.Join(dir, entry.Name())
			if filepath.Clean(p) == cleanSkip {
				continue
			}
			fi, err := os.Lstat(p)
			if err != nil {
				continue
			}
			st, ok := fi.Sys().(*syscall.Stat_t)
			if !ok || st.Uid != uid {
				continue
			}
			_ = os.RemoveAll(p)
		}
	}
}

func extractVulnID(raw json.RawMessage) (string, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return "", errors.New("must be a JSON object")
	}
	var obj struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(trimmed, &obj); err != nil {
		return "", err
	}
	if obj.ID == "" {
		return "", errors.New("missing id field")
	}

	return obj.ID, nil
}

// mkdirAll0755 creates dir and any missing parent directories under root, ensuring each created
// directory has exact mode 0755 regardless of process umask.
func mkdirAll0755(root, dir string) error {
	cleanRoot := filepath.Clean(root)
	cleanDir := filepath.Clean(dir)
	if cleanDir == cleanRoot {
		return nil
	}
	rel, err := filepath.Rel(cleanRoot, cleanDir)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return fmt.Errorf("directory %q escapes %q", dir, root)
	}
	cur := cleanRoot
	for part := range strings.SplitSeq(rel, string(os.PathSeparator)) {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		if err := os.Mkdir(cur, 0755); err != nil && !errors.Is(err, os.ErrExist) {
			return err
		}
		if err := os.Chmod(cur, 0755); err != nil {
			return err
		}
	}

	return nil
}

// extractTarZstSafely extracts a .tar.zst archive into destDir with strict security checks:
// - Rejects path traversal, symlinks, hardlinks, devices, FIFOs, and special permission bits.
// - Writes all directories as 0755 and all files as 0644 (read-only to non-root UIDs).
// - Enforces cumulative extracted byte and entry count limits across all packs in the request.
func extractTarZstSafely(zstBytes []byte, destDir string, totalExtracted *int64, maxBytes int64, totalEntries *int, maxEntries int) error {
	if err := os.Mkdir(destDir, 0755); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := os.Chmod(destDir, 0755); err != nil {
		return err
	}

	zr, err := zstd.NewReader(
		bytes.NewReader(zstBytes),
		zstd.WithDecoderMaxWindow(maxZstdWindowBytes),
		zstd.WithDecoderMaxMemory(maxZstdMemoryBytes),
	)
	if err != nil {
		return fmt.Errorf("invalid zstd stream: %w", err)
	}
	defer zr.Close()

	remaining := maxBytes - *totalExtracted
	if remaining < 0 {
		return fmt.Errorf("extracted size limit (%d bytes) exceeded", maxBytes)
	}

	tr := tar.NewReader(io.LimitReader(zr, remaining+1))
	cleanDest := filepath.Clean(destDir)
	destPrefix := cleanDest + string(os.PathSeparator)

	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("invalid tar entry: %w", err)
		}

		// Ignore PAX extended metadata headers.
		if hdr.Typeflag == tar.TypeXHeader || hdr.Typeflag == tar.TypeXGlobalHeader {
			continue
		}

		if strings.ContainsRune(hdr.Name, '\x00') {
			return fmt.Errorf("illegal NUL byte in tar path: %q", hdr.Name)
		}

		name := filepath.Clean(hdr.Name)
		if name == "." {
			continue
		}
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(os.PathSeparator)) {
			return fmt.Errorf("illegal tar path: %q", hdr.Name)
		}

		targetPath := filepath.Join(cleanDest, name)
		if !strings.HasPrefix(targetPath, destPrefix) {
			return fmt.Errorf("tar path escapes target directory: %q", hdr.Name)
		}

		*totalEntries++
		if maxEntries > 0 && *totalEntries > maxEntries {
			return fmt.Errorf("extracted entry limit (%d entries) exceeded", maxEntries)
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAll0755(cleanDest, targetPath); err != nil {
				return err
			}
		case tar.TypeReg:
			if hdr.Size < 0 {
				return fmt.Errorf("negative file size in tar: %q", hdr.Name)
			}
			if err := mkdirAll0755(cleanDest, filepath.Dir(targetPath)); err != nil {
				return err
			}
			budget := maxBytes - *totalExtracted
			if budget < 0 {
				return fmt.Errorf("extracted size limit (%d bytes) exceeded", maxBytes)
			}

			outFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err != nil {
				return err
			}
			written, copyErr := io.Copy(outFile, io.LimitReader(tr, budget+1))
			closeErr := outFile.Close()
			if copyErr != nil {
				return copyErr
			}
			if closeErr != nil {
				return closeErr
			}
			*totalExtracted += written
			if *totalExtracted > maxBytes {
				return fmt.Errorf("extracted size limit (%d bytes) exceeded", maxBytes)
			}
			if err := os.Chmod(targetPath, 0644); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported tar entry type %q for %q", hdr.Typeflag, hdr.Name)
		}
	}

	return nil
}

func probeCapability(selfExe string, attr *syscall.SysProcAttr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, selfExe, "-probe-noop")
	cmd.SysProcAttr = attr

	return cmd.Run()
}

func main() {
	defaultPort := 8080
	if envPort := os.Getenv("PORT"); envPort != "" {
		if p, err := strconv.Atoi(envPort); err == nil && p > 0 {
			defaultPort = p
		}
	}

	var (
		port        int
		pythonBin   string
		scriptPath  string
		maxRequests int64
		timeout     time.Duration
		noSetuid    bool
		reapUIDFlag bool
		probeNoop   bool
	)

	flag.IntVar(&port, "port", defaultPort, "HTTP listen port.")
	flag.StringVar(&pythonBin, "python-bin", "python3", "Python interpreter binary.")
	flag.StringVar(&scriptPath, "script-path", "/usr/local/bin/generate_signatures.py", "Path to generate_signatures.py.")
	flag.Int64Var(&maxRequests, "max-requests", 0, "Maximum requests before graceful exit (0 = unlimited warm Mode B).")
	flag.DurationVar(&timeout, "timeout", defaultTimeout, "Per-request child execution timeout.")
	flag.BoolVar(&noSetuid, "no-setuid", false, "Allow running without UID switching (only permitted when non-root for local tests).")
	flag.BoolVar(&reapUIDFlag, "reap-uid", false, "Internal helper: kill all processes owned by current non-root UID and exit.")
	flag.BoolVar(&probeNoop, "probe-noop", false, "Internal helper: exit 0 immediately for startup capability probing.")
	flag.Parse()

	if probeNoop {
		return
	}

	if reapUIDFlag {
		// Safety guard: NEVER call kill(-1, SIGKILL) as root (UID 0).
		if os.Getuid() == 0 || os.Geteuid() == 0 {
			os.Exit(2)
		}
		_ = syscall.Kill(-1, syscall.SIGKILL)

		return
	}

	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	selfExe, err := os.Executable()
	if err != nil {
		logger.FatalContext(ctx, "Failed to resolve executable path", slog.Any("error", err))
	}

	isRoot := os.Geteuid() == 0
	if isRoot && noSetuid {
		logger.FatalContext(ctx, "Refusing to run with -no-setuid as UID 0")
	}
	if !isRoot && !noSetuid {
		logger.FatalContext(ctx, "vanir_sandbox must run as UID 0 to isolate per-request UIDs (pass -no-setuid only for unprivileged local tests)")
	}

	useSetuid := isRoot
	supportsNetNS := false

	if useSetuid {
		syscall.Umask(0022)
		if err := probeCapability(selfExe, &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: probeUID, Gid: probeUID, Groups: []uint32{}},
		}); err != nil {
			logger.FatalContext(ctx, "CAP_SETUID/CAP_SETGID probe failed (Cloud Run Gen2 is required for Mode B UID isolation)", slog.Any("error", err))
		}

		if err := probeCapability(selfExe, &syscall.SysProcAttr{
			Credential: &syscall.Credential{Uid: probeUID, Gid: probeUID, Groups: []uint32{}},
			Cloneflags: syscall.CLONE_NEWNET | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		}); err != nil {
			logger.WarnContext(ctx, "CLONE_NEWNET probe failed; continuing without per-request network namespace isolation", slog.Any("error", err))
		} else {
			supportsNetNS = true
		}
	}

	// Create a private supervisor-owned base directory (0711 when root, 0700 when unprivileged)
	// so untrusted child UIDs can traverse to their own job/repo paths but cannot list, pre-create,
	// rename, or symlink-swap sibling request directories inside shared /tmp.
	baseWorkDir, err := os.MkdirTemp("", "vanir-sandbox-root-*")
	if err != nil {
		logger.FatalContext(ctx, "Failed to create private sandbox base directory", slog.Any("error", err))
	}
	baseMode := os.FileMode(0700)
	if useSetuid {
		baseMode = 0711
	}
	if err := os.Chmod(baseWorkDir, baseMode); err != nil {
		_ = os.RemoveAll(baseWorkDir)
		logger.FatalContext(ctx, "Failed to chmod private sandbox base directory", slog.Any("error", err))
	}
	defer os.RemoveAll(baseWorkDir)

	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	sb := &sandboxServer{
		pythonBin:     pythonBin,
		scriptPath:    scriptPath,
		baseWorkDir:   baseWorkDir,
		timeout:       timeout,
		maxRequests:   maxRequests,
		useSetuid:     useSetuid,
		supportsNetNS: supportsNetNS,
		selfExe:       selfExe,
		onMaxRequests: srvCancel,
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", port),
		Handler:           sb.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.InfoContext(ctx, "Starting vanir_sandbox server",
		slog.Int("port", port),
		slog.Bool("use_setuid", useSetuid),
		slog.Bool("supports_netns", supportsNetNS),
		slog.Int64("max_requests", maxRequests))

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.FatalContext(ctx, "vanir_sandbox server failed", slog.Any("error", err))
		}
	}()

	<-srvCtx.Done()
	stop()
	logger.InfoContext(context.Background(), "Shutting down vanir_sandbox server")

	shutCtx, shutCancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer shutCancel()
	if err := httpServer.Shutdown(shutCtx); err != nil {
		logger.ErrorContext(context.Background(), "Graceful shutdown failed", slog.Any("error", err))
	}
}
