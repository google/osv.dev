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

// Package main implements the untrusted Vanir sandbox HTTP server for Cloud Run Gen2.
// Each request processes a single vulnerability record under a unique non-root Linux UID,
// isolated work directory, stripped environment, and fail-closed post-request UID process
// reaping. Authentication is enforced by Cloud Run IAM (roles/run.invoker).
//
// TODO: Integrate with gitter's /commit-pack endpoint (--git-instead-ofs) so Git-only
// requests can run offline inside an empty CLONE_NEWNET network namespace.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/logger"
)

const (
	maxRequestBytes  = 4 << 20  // 4 MiB max HTTP request payload
	maxOutputBytes   = 4 << 20  // 4 MiB max output.json read from child
	maxChildLogBytes = 64 << 10 // 64 KiB max child output buffered in memory
	defaultTimeout   = 25 * time.Minute
	shutdownTimeout  = 8 * time.Second // Fits within Cloud Run's 10s SIGTERM grace period
	uidBase          = 10000
	uidSpan          = 50000
	probeUID         = 65534 // nobody
)

var errChildTimeout = errors.New("vanir sandbox execution timed out")

// cappedBuffer buffers up to limit bytes and silently discards excess writes so a
// noisy child cannot OOM the supervisor or stall on a full stdout/stderr pipe.
// Safe without a mutex when shared by cmd.Stdout and cmd.Stderr (os/exec uses one pipe).
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	if rem := b.limit - b.buf.Len(); rem > 0 {
		if len(p) > rem {
			_, _ = b.buf.Write(p[:rem])
			b.truncated = true
		} else {
			_, _ = b.buf.Write(p)
		}
	} else {
		b.truncated = true
	}

	return len(p), nil
}

func (b *cappedBuffer) String() string {
	if b.truncated {
		return strings.ToValidUTF8(b.buf.String(), "") + "... [truncated]"
	}

	return b.buf.String()
}

// GenerateRequest is the JSON request body for POST /v1/generate.
type GenerateRequest struct {
	Vulnerability json.RawMessage `json:"vulnerability"` // Single OSV JSON object
}

// GenerateResponse is the JSON response body for POST /v1/generate.
type GenerateResponse struct {
	Signatures json.RawMessage `json:"signatures"` // affected_idx_str -> signature objects
}

type sandboxServer struct {
	pythonBin   string
	scriptPath  string
	baseWorkDir string
	timeout     time.Duration
	useSetuid   bool
	selfExe     string
	onShutdown  func()

	execMu  sync.Mutex
	seq     atomic.Int64
	tainted atomic.Bool
}

func (s *sandboxServer) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		if s.tainted.Load() {
			http.Error(w, "sandbox tainted", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/generate", s.handleGenerate)

	return mux
}

func (s *sandboxServer) handleGenerate(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	if s.tainted.Load() {
		http.Error(w, "sandbox tainted", http.StatusServiceUnavailable)
		return
	}

	// Reject concurrent requests immediately so an in-flight child cannot queue
	// follow-up requests against loopback while running.
	if !s.execMu.TryLock() {
		http.Error(w, "sandbox busy", http.StatusServiceUnavailable)
		return
	}
	defer s.execMu.Unlock()

	if s.tainted.Load() {
		http.Error(w, "sandbox tainted", http.StatusServiceUnavailable)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxRequestBytes)
	defer r.Body.Close()

	var req GenerateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
			http.Error(w, "request body too large", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, fmt.Sprintf("invalid JSON request: %v", err), http.StatusBadRequest)

		return
	}

	var meta struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(req.Vulnerability, &meta); err != nil || meta.ID == "" {
		http.Error(w, "invalid vulnerability object: missing id", http.StatusBadRequest)
		return
	}

	n := s.seq.Add(1)
	//nolint:gosec // G115: uidBase + (n % uidSpan) is always in [10000, 59999].
	uid := uint32(uidBase + (n % uidSpan))

	sigs, err := s.executeRequest(ctx, n, uid, meta.ID, &req)
	if err != nil {
		logger.ErrorContext(ctx, "Sandbox execution failed",
			slog.String("vuln_id", meta.ID),
			slog.Int64("seq", n),
			slog.Any("error", err))
		status := http.StatusInternalServerError
		if errors.Is(err, errChildTimeout) {
			status = http.StatusGatewayTimeout
		}
		http.Error(w, err.Error(), status)

		return
	}

	respBytes, err := json.Marshal(GenerateResponse{Signatures: sigs})
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal response: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respBytes)
}

func (s *sandboxServer) executeRequest(ctx context.Context, seq int64, uid uint32, vulnID string, req *GenerateRequest) (json.RawMessage, error) {
	jobDir := filepath.Join(s.baseWorkDir, fmt.Sprintf("vanir-job-%d", seq))
	workDir := filepath.Join(jobDir, "work")
	gitWorkDir := filepath.Join(workDir, "git-work")
	defer os.RemoveAll(jobDir)

	// Root-owned 0711 jobDir prevents child from unlinking or listing IPC files while
	// allowing traversal into child-owned 0700 workDir and gitWorkDir.
	for _, d := range []struct {
		path string
		mode os.FileMode
	}{
		{jobDir, 0711},
		{workDir, 0700},
		{gitWorkDir, 0700},
	} {
		if err := os.Mkdir(d.path, d.mode); err != nil {
			return nil, fmt.Errorf("failed to create %s: %w", filepath.Base(d.path), err)
		}
	}

	inputPath := filepath.Join(jobDir, "input.json")
	outputPath := filepath.Join(jobDir, "output.json")

	batchPayload, err := json.Marshal([]json.RawMessage{req.Vulnerability})
	if err != nil {
		return nil, fmt.Errorf("failed to marshal input batch: %w", err)
	}
	if err := os.WriteFile(inputPath, batchPayload, 0600); err != nil {
		return nil, fmt.Errorf("failed to write input.json: %w", err)
	}
	if err := os.WriteFile(outputPath, nil, 0600); err != nil {
		return nil, fmt.Errorf("failed to pre-create output.json: %w", err)
	}

	if s.useSetuid {
		if err := os.Chown(inputPath, 0, int(uid)); err != nil {
			return nil, fmt.Errorf("failed to chown input.json: %w", err)
		}
		if err := os.Chmod(inputPath, 0640); err != nil {
			return nil, fmt.Errorf("failed to chmod input.json: %w", err)
		}
		for _, p := range []string{workDir, gitWorkDir, outputPath} {
			if err := os.Chown(p, int(uid), int(uid)); err != nil {
				return nil, fmt.Errorf("failed to chown %s: %w", p, err)
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
	)
	cmd.Env = []string{
		"PATH=/app/.venv/bin:/usr/local/bin:/usr/bin:/bin",
		"HOME=" + workDir,
		"TMPDIR=" + workDir,
		"PYTHONDONTWRITEBYTECODE=1",
		"GIT_TERMINAL_PROMPT=0",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_ALLOW_PROTOCOL=https:http",
	}

	sysProcAttr := &syscall.SysProcAttr{Setpgid: true}
	if s.useSetuid {
		sysProcAttr.Credential = &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}}
	}
	cmd.SysProcAttr = sysProcAttr
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = 5 * time.Second

	outBuf := &cappedBuffer{limit: maxChildLogBytes}
	cmd.Stdout = outBuf
	cmd.Stderr = outBuf

	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start sandbox child: %w", err)
	}

	waitErr := cmd.Wait()
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	if s.useSetuid {
		if err := s.reapUID(context.WithoutCancel(ctx), uid); err != nil {
			logger.ErrorContext(ctx, "UID process reaping failed; marking instance tainted and shutting down",
				slog.String("vuln_id", vulnID),
				slog.Uint64("uid", uint64(uid)),
				slog.Any("error", err))
			s.tainted.Store(true)
			if s.onShutdown != nil {
				s.onShutdown()
			}

			return nil, fmt.Errorf("sandbox process reaping failed: %w", err)
		}
		sweepUIDTempFiles(uid)
	}

	if waitErr != nil {
		logger.WarnContext(ctx, "Vanir sandbox child failed",
			slog.String("vuln_id", vulnID),
			slog.Any("error", waitErr),
			slog.String("output", outBuf.String()))
		if errors.Is(cmdCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return nil, fmt.Errorf("%w: %w", errChildTimeout, waitErr)
		}

		return nil, fmt.Errorf("vanir sandbox execution failed: %w", waitErr)
	}

	outFile, err := os.Open(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open output.json: %w", err)
	}
	defer outFile.Close()
	outputBytes, err := io.ReadAll(io.LimitReader(outFile, maxOutputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read output.json: %w", err)
	}
	if len(outputBytes) > maxOutputBytes {
		return nil, fmt.Errorf("output.json exceeds max size (%d bytes)", maxOutputBytes)
	}

	var rawOutput map[string]json.RawMessage
	if err := json.Unmarshal(outputBytes, &rawOutput); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output.json: %w", err)
	}

	sigs := bytes.TrimSpace(rawOutput[vulnID])
	if len(sigs) == 0 || bytes.Equal(sigs, []byte("null")) {
		sigs = json.RawMessage("{}")
	}

	return sigs, nil
}

// sweepUIDTempFiles removes any top-level entries owned by uid left behind in shared
// world-writable tmpfs directories across warm container requests.
func sweepUIDTempFiles(uid uint32) {
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm", "/run/lock"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			fullPath := filepath.Join(dir, entry.Name())
			fi, err := os.Lstat(fullPath)
			if err != nil {
				continue
			}
			if st, ok := fi.Sys().(*syscall.Stat_t); ok && st.Uid == uid {
				_ = os.RemoveAll(fullPath)
			}
		}
	}
}

// reapUID spawns a short-lived helper running as the given non-root UID that calls
// kill(-1, SIGKILL), atomically killing any surviving processes owned by that UID.
func (s *sandboxServer) reapUID(parentCtx context.Context, uid uint32) error {
	if uid == 0 || s.selfExe == "" {
		return errors.New("reapUID requires non-zero uid and selfExe")
	}
	ctx, cancel := context.WithTimeout(parentCtx, 5*time.Second)
	defer cancel()

	//nolint:gosec // G204: selfExe is our own binary path resolved at startup.
	cmd := exec.CommandContext(ctx, s.selfExe, "-reap-uid")
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: uid, Gid: uid, Groups: []uint32{}},
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("reap-uid helper failed for uid %d: %w", uid, err)
	}

	return nil
}

func probeSetuid(selfExe string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, selfExe, "-probe-noop")
	cmd.Env = []string{}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Credential: &syscall.Credential{Uid: probeUID, Gid: probeUID, Groups: []uint32{}},
	}

	return cmd.Run()
}

func main() {
	defaultPort := 8080
	if p, err := strconv.Atoi(os.Getenv("PORT")); err == nil && p > 0 {
		defaultPort = p
	}

	port := flag.Int("port", defaultPort, "HTTP listen port.")
	pythonBin := flag.String("python-bin", "python3", "Python interpreter binary.")
	scriptPath := flag.String("script-path", "/usr/local/bin/generate_signatures.py", "Path to generate_signatures.py.")
	timeout := flag.Duration("timeout", defaultTimeout, "Per-request child execution timeout.")
	noSetuid := flag.Bool("no-setuid", false, "Allow running without UID switching (only permitted when non-root for local tests).")
	reapUIDFlag := flag.Bool("reap-uid", false, "Internal helper: kill all processes owned by current non-root UID and exit.")
	probeNoop := flag.Bool("probe-noop", false, "Internal helper: exit 0 immediately for startup capability probing.")
	flag.Parse()

	if *probeNoop {
		return
	}
	if *reapUIDFlag {
		// Safety guard: NEVER call kill(-1, SIGKILL) as root (UID 0).
		if os.Getuid() == 0 || os.Geteuid() == 0 {
			os.Exit(2)
		}
		if err := syscall.Kill(-1, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
			os.Exit(3)
		}

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
	if isRoot && *noSetuid {
		logger.FatalContext(ctx, "Refusing to run with -no-setuid as UID 0")
	}
	if !isRoot && !*noSetuid {
		logger.FatalContext(ctx, "vanir_sandbox must run as UID 0 to isolate per-request UIDs (pass -no-setuid only for unprivileged local tests)")
	}

	useSetuid := isRoot
	if useSetuid {
		syscall.Umask(0022)
		if err := probeSetuid(selfExe); err != nil {
			logger.FatalContext(ctx, "CAP_SETUID/CAP_SETGID probe failed (Cloud Run Gen2 is required for UID isolation)", slog.Any("error", err))
		}
	}

	baseWorkDir, err := os.MkdirTemp("", "vanir-sandbox-root-*")
	if err != nil {
		logger.FatalContext(ctx, "Failed to create private sandbox base directory", slog.Any("error", err))
	}
	if useSetuid {
		if err := os.Chmod(baseWorkDir, 0711); err != nil {
			_ = os.RemoveAll(baseWorkDir)
			logger.FatalContext(ctx, "Failed to chmod private sandbox base directory", slog.Any("error", err))
		}
	}
	defer os.RemoveAll(baseWorkDir)

	srvCtx, srvCancel := context.WithCancel(ctx)
	defer srvCancel()

	sb := &sandboxServer{
		pythonBin:   *pythonBin,
		scriptPath:  *scriptPath,
		baseWorkDir: baseWorkDir,
		timeout:     *timeout,
		useSetuid:   useSetuid,
		selfExe:     selfExe,
		onShutdown:  srvCancel,
	}

	httpServer := &http.Server{
		Addr:              fmt.Sprintf(":%d", *port),
		Handler:           sb.routes(),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       60 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}

	logger.InfoContext(ctx, "Starting vanir_sandbox server",
		slog.Int("port", *port),
		slog.Bool("use_setuid", useSetuid))

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
