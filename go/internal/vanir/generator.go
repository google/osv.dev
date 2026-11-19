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
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

const (
	defaultBatchTimeout  = 30 * time.Minute
	maxPythonOutputBytes = 64 << 20 // 64 MiB max batch output.json
	maxPythonLogBytes    = 64 << 10 // 64 KiB max stdout/stderr captured from Python child
)

type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
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

func (b *cappedBuffer) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()

	return b.buf.Len()
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.truncated {
		return b.buf.String() + "... [truncated]"
	}

	return b.buf.String()
}

// SignatureMap maps vulnerability ID -> affected[] index -> list of Vanir signature objects.
type SignatureMap map[string]map[int][]*structpb.Value

// SignatureGenerator abstracts the Vanir signature generation engine.
type SignatureGenerator interface {
	GenerateBatch(ctx context.Context, vulns []*osvschema.Vulnerability, gitWorkingDir string) (SignatureMap, error)
}

// PythonGenerator shells out to the Python Vanir helper script to generate signatures for a batch.
type PythonGenerator struct {
	PythonBin  string
	ScriptPath string
	Timeout    time.Duration
}

var _ SignatureGenerator = (*PythonGenerator)(nil)

func NewPythonGenerator(pythonBin, scriptPath string) *PythonGenerator {
	if pythonBin == "" {
		pythonBin = "python3"
	}
	if scriptPath == "" {
		scriptPath = "/usr/local/bin/generate_signatures.py"
	}

	return &PythonGenerator{
		PythonBin:  pythonBin,
		ScriptPath: scriptPath,
		Timeout:    defaultBatchTimeout,
	}
}

func (g *PythonGenerator) GenerateBatch(ctx context.Context, vulns []*osvschema.Vulnerability, workingDir string) (SignatureMap, error) {
	if len(vulns) == 0 {
		return SignatureMap{}, nil
	}

	type preparedVuln struct {
		orig      *osvschema.Vulnerability
		sanitized *osvschema.Vulnerability
		indexMap  []int
	}

	prepared := make([]preparedVuln, 0, len(vulns))
	for _, v := range vulns {
		if v == nil {
			continue
		}
		sanitized, gitTargets, needsNetwork, indexMap := sanitizeForVanirWithIndexMap(v)
		if len(gitTargets) == 0 && !needsNetwork {
			continue
		}
		prepared = append(prepared, preparedVuln{
			orig:      v,
			sanitized: sanitized,
			indexMap:  indexMap,
		})
	}
	if len(prepared) == 0 {
		return SignatureMap{}, nil
	}

	ipcDir, err := os.MkdirTemp(workingDir, "vanir-ipc-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create IPC temp dir: %w", err)
	}
	defer os.RemoveAll(ipcDir)
	gitDir, err := os.MkdirTemp(workingDir, "vanir-git-*")
	if err != nil {
		return nil, fmt.Errorf("failed to create git temp dir: %w", err)
	}
	defer os.RemoveAll(gitDir)

	inputPath := filepath.Join(ipcDir, "input.json")
	outputPath := filepath.Join(ipcDir, "output.json")

	marshaler := protojson.MarshalOptions{UseProtoNames: true}
	rawMessages := make([]json.RawMessage, 0, len(prepared))
	for _, item := range prepared {
		b, err := marshaler.Marshal(item.sanitized)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vulnerability %s to JSON: %w", item.orig.GetId(), err)
		}
		rawMessages = append(rawMessages, json.RawMessage(b))
	}

	inputData, err := json.Marshal(rawMessages)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal batch JSON array: %w", err)
	}

	if err := os.WriteFile(inputPath, inputData, 0600); err != nil {
		return nil, fmt.Errorf("failed to write input JSON file: %w", err)
	}

	timeout := g.Timeout
	if timeout <= 0 {
		timeout = defaultBatchTimeout
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	//nolint:gosec // G204: PythonBin and ScriptPath are trusted service configuration paths.
	cmd := exec.CommandContext(
		cmdCtx,
		g.PythonBin,
		g.ScriptPath,
		"--input", inputPath,
		"--output", outputPath,
		"--git-working-dir", gitDir,
	)
	cmd.WaitDelay = 10 * time.Second
	stderr := &cappedBuffer{limit: maxPythonLogBytes}
	cmd.Stdout = stderr
	cmd.Stderr = stderr

	if err := cmd.Run(); err != nil {
		logger.ErrorContext(ctx, "Python Vanir signature generation failed",
			slog.Any("error", err),
			slog.String("output", stderr.String()))

		return nil, fmt.Errorf("vanir python runner failed: %w", err)
	}

	if stderr.Len() > 0 {
		logger.DebugContext(ctx, "Python Vanir runner output", slog.String("output", stderr.String()))
	}

	fd, err := syscall.Open(outputPath, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to open output JSON file: %w", err)
	}
	outFile := os.NewFile(uintptr(fd), outputPath)
	defer outFile.Close()

	fi, err := outFile.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat output JSON file: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, errors.New("output JSON file is not a regular file")
	}

	outputData, err := io.ReadAll(io.LimitReader(outFile, maxPythonOutputBytes+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read output JSON file: %w", err)
	}
	if len(outputData) > maxPythonOutputBytes {
		return nil, fmt.Errorf("output JSON file exceeds max size (%d bytes)", maxPythonOutputBytes)
	}

	var rawOutput map[string]map[string][]any
	if err := json.Unmarshal(outputData, &rawOutput); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output JSON: %w", err)
	}

	// Pin output strictly to the requested vulnerabilities and validate all signatures.
	result := make(SignatureMap, len(prepared))
	for _, item := range prepared {
		vulnID := item.orig.GetId()
		affectedMap := rawOutput[vulnID]
		if len(affectedMap) == 0 {
			continue
		}
		remapped, err := remapAffectedIndices(item.sanitized, affectedMap, item.indexMap)
		if err != nil {
			return nil, fmt.Errorf("invalid affected index for %s: %w", vulnID, err)
		}
		validated, err := ValidateSignatures(item.orig, remapped)
		if err != nil {
			return nil, fmt.Errorf("signature validation failed for %s: %w", vulnID, err)
		}
		if len(validated) > 0 {
			result[vulnID] = validated
		}
	}

	return result, nil
}
