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
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
)

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
	}
}

func (g *PythonGenerator) GenerateBatch(ctx context.Context, vulns []*osvschema.Vulnerability, workingDir string) (SignatureMap, error) {
	if len(vulns) == 0 {
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
	rawMessages := make([]json.RawMessage, 0, len(vulns))
	for _, v := range vulns {
		b, err := marshaler.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal vulnerability %s to JSON: %w", v.GetId(), err)
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

	//nolint:gosec // G204: PythonBin and ScriptPath are trusted service configuration paths.
	cmd := exec.CommandContext(
		ctx,
		g.PythonBin,
		g.ScriptPath,
		"--input", inputPath,
		"--output", outputPath,
		"--git-working-dir", gitDir,
	)
	var stderr bytes.Buffer
	cmd.Stdout = &stderr
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		logger.ErrorContext(ctx, "Python Vanir signature generation failed",
			slog.Any("error", err),
			slog.String("output", stderr.String()))

		return nil, fmt.Errorf("vanir python runner failed: %w", err)
	}

	if stderr.Len() > 0 {
		logger.DebugContext(ctx, "Python Vanir runner output", slog.String("output", stderr.String()))
	}

	outputData, err := os.ReadFile(outputPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read output JSON file: %w", err)
	}

	var rawOutput map[string]map[string][]any
	if err := json.Unmarshal(outputData, &rawOutput); err != nil {
		return nil, fmt.Errorf("failed to unmarshal output JSON: %w", err)
	}

	result := make(SignatureMap, len(rawOutput))
	for vulnID, affectedMap := range rawOutput {
		idxMap := make(map[int][]*structpb.Value, len(affectedMap))
		for idxStr, sigList := range affectedMap {
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return nil, fmt.Errorf("invalid affected index %q for %s: %w", idxStr, vulnID, err)
			}
			vals := make([]*structpb.Value, 0, len(sigList))
			for _, rawSig := range sigList {
				val, err := structpb.NewValue(rawSig)
				if err != nil {
					return nil, fmt.Errorf("failed to convert signature to structpb.Value for %s: %w", vulnID, err)
				}
				vals = append(vals, val)
			}
			if len(vals) > 0 {
				idxMap[idx] = vals
			}
		}
		if len(idxMap) > 0 {
			result[vulnID] = idxMap
		}
	}

	return result, nil
}
