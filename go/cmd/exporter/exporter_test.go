package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWriter_GCS_StreamUpload(t *testing.T) {
	storage := testutils.NewMockStorage()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "sample.zip")
	content := []byte("zip binary contents")
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	runWriter(t, storage, []writeMsg{
		{path: "all.zip", mimeType: "application/zip", filePath: tmpFile},
	})

	objPath := filepath.Join("out", "all.zip")
	got, err := storage.ReadObject(t.Context(), objPath)
	if err != nil {
		t.Fatalf("ReadObject(%s) failed: %v", objPath, err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("expected %q, got %q", content, got)
	}
}

func TestWriter_GCS_StreamSkipsUnchanged(t *testing.T) {
	storage := testutils.NewMockStorage()
	tmpDir := t.TempDir()
	tmpFile := filepath.Join(tmpDir, "sample.zip")
	content := []byte("zip binary contents")
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		t.Fatalf("failed to write temp file: %v", err)
	}

	objPath := filepath.Join("out", "all.zip")
	if err := storage.WriteObject(t.Context(), objPath, content, nil); err != nil {
		t.Fatalf("setup WriteObject failed: %v", err)
	}
	attrsBefore, _ := storage.ReadObjectAttrs(t.Context(), objPath)

	runWriter(t, storage, []writeMsg{
		{path: "all.zip", mimeType: "application/zip", filePath: tmpFile},
	})

	attrsAfter, err := storage.ReadObjectAttrs(t.Context(), objPath)
	if err != nil {
		t.Fatalf("ReadObjectAttrs failed: %v", err)
	}
	if attrsAfter.Generation != attrsBefore.Generation {
		t.Errorf("expected generation %d (skipped), got %d", attrsBefore.Generation, attrsAfter.Generation)
	}
}

func TestExporterPipeline_EndToEnd(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	scratchDir := t.TempDir()
	vulnStorage := testutils.NewMockStorage()
	outStorage := testutils.NewMockStorage()

	time1 := time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC)
	time2 := time.Date(2023, 2, 1, 12, 0, 0, 0, time.UTC)

	// Create test vulnerability 1: PyPI
	vuln1 := &osvschema.Vulnerability{
		Id:       "GHSA-pypi-1",
		Modified: timestamppb.New(time1),
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "PyPI",
					Name:      "requests",
				},
			},
		},
	}
	pb1, err := proto.Marshal(vuln1)
	if err != nil {
		t.Fatalf("failed to marshal proto: %v", err)
	}
	_ = vulnStorage.WriteObject(ctx, "all/pb/vuln1", pb1, nil)

	// Create test vulnerability 2: npm and GIT with Vanir signatures
	vanirField, _ := structpb.NewValue("test-signature")
	vuln2 := &osvschema.Vulnerability{
		Id:       "GHSA-npm-git-2",
		Modified: timestamppb.New(time2),
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "npm",
					Name:      "lodash",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_GIT,
					},
				},
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"vanir_signatures": vanirField,
					},
				},
			},
		},
	}
	pb2, err := proto.Marshal(vuln2)
	if err != nil {
		t.Fatalf("failed to marshal proto: %v", err)
	}
	_ = vulnStorage.WriteObject(ctx, "all/pb/vuln2", pb2, nil)

	gcsPathToProcessorCh := make(chan string, 10)
	processorToRouterCh := make(chan processedVuln, 10)
	writeCh := make(chan writeMsg, 100)

	var processorWg sync.WaitGroup
	processorWg.Add(1)
	go downloadThenProcessor(ctx, cancel, vulnStorage, scratchDir, gcsPathToProcessorCh, processorToRouterCh, writeCh, &processorWg)

	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go writer(ctx, cancel, writeCh, outStorage, "export", &writerWg)

	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, processorToRouterCh, writeCh, scratchDir, &routerWg)

	gcsPathToProcessorCh <- "all/pb/vuln1"
	gcsPathToProcessorCh <- "all/pb/vuln2"
	close(gcsPathToProcessorCh)

	processorWg.Wait()
	close(processorToRouterCh)
	routerWg.Wait()
	close(writeCh)
	writerWg.Wait()

	// 1. Verify individual JSON outputs
	pypiJSON, err := outStorage.ReadObject(ctx, "export/PyPI/GHSA-pypi-1.json")
	if err != nil {
		t.Fatalf("expected PyPI/GHSA-pypi-1.json in storage: %v", err)
	}
	if !bytes.Contains(pypiJSON, []byte(`"id":"GHSA-pypi-1"`)) {
		t.Errorf("PyPI JSON content mismatch: %s", string(pypiJSON))
	}

	npmJSON, err := outStorage.ReadObject(ctx, "export/npm/GHSA-npm-git-2.json")
	if err != nil {
		t.Fatalf("expected npm/GHSA-npm-git-2.json in storage: %v", err)
	}
	if !bytes.Contains(npmJSON, []byte(`"id":"GHSA-npm-git-2"`)) {
		t.Errorf("npm JSON content mismatch: %s", string(npmJSON))
	}

	// 2. Verify all.zip contains all JSON files
	allZipBytes, err := outStorage.ReadObject(ctx, "export/all.zip")
	if err != nil {
		t.Fatalf("expected all.zip: %v", err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(allZipBytes), int64(len(allZipBytes)))
	if err != nil {
		t.Fatalf("failed to open all.zip: %v", err)
	}
	zipNames := make([]string, 0, len(zipReader.File))
	for _, f := range zipReader.File {
		zipNames = append(zipNames, f.Name)
		rc, err := f.Open()
		if err != nil {
			t.Fatalf("failed to open zip entry %s: %v", f.Name, err)
		}
		entryBytes, err := io.ReadAll(rc)
		_ = rc.Close()
		if err != nil {
			t.Fatalf("failed to read/decompress zip entry %s: %v", f.Name, err)
		}
		var parsed map[string]any
		if err := json.Unmarshal(entryBytes, &parsed); err != nil {
			t.Fatalf("failed to parse JSON from zip entry %s: %v", f.Name, err)
		}
		if parsed["id"] != f.Name[:len(f.Name)-len(".json")] {
			t.Errorf("expected id %s in %s, got %v", f.Name[:len(f.Name)-len(".json")], f.Name, parsed["id"])
		}
	}
	if len(zipNames) != 2 {
		t.Errorf("expected 2 files in all.zip, got %v", zipNames)
	}

	// 3. Verify modified_id.csv ordering (descending by modified time)
	csvBytes, err := outStorage.ReadObject(ctx, "export/modified_id.csv")
	if err != nil {
		t.Fatalf("expected modified_id.csv: %v", err)
	}
	csvReader := csv.NewReader(bytes.NewReader(csvBytes))
	records, err := csvReader.ReadAll()
	if err != nil {
		t.Fatalf("failed to parse modified_id.csv: %v", err)
	}
	// vuln2 has later modified time, so its ecosystems (GIT, npm) should appear before PyPI
	if len(records) < 3 {
		t.Fatalf("expected at least 3 records in modified_id.csv, got %d", len(records))
	}
	if records[0][0] != time2.Format(time.RFC3339Nano) {
		t.Errorf("expected first record to be time2, got %s", records[0][0])
	}

	// 4. Verify ecosystems.txt
	ecoTxtBytes, err := outStorage.ReadObject(ctx, "export/ecosystems.txt")
	if err != nil {
		t.Fatalf("expected ecosystems.txt: %v", err)
	}
	expectedEco := "GIT\nPyPI\nnpm\n"
	if string(ecoTxtBytes) != expectedEco {
		t.Errorf("expected %q in ecosystems.txt, got %q", expectedEco, string(ecoTxtBytes))
	}

	// 5. Verify Vanir signatures file (GIT/osv_git.json)
	vanirBytes, err := outStorage.ReadObject(ctx, "export/GIT/osv_git.json")
	if err != nil {
		t.Fatalf("expected GIT/osv_git.json: %v", err)
	}
	var vanirList []map[string]any
	if err := json.Unmarshal(vanirBytes, &vanirList); err != nil {
		t.Fatalf("failed to unmarshal vanir JSON: %v", err)
	}
	if len(vanirList) != 1 || vanirList[0]["id"] != "GHSA-npm-git-2" {
		t.Errorf("unexpected vanir content: %s", string(vanirBytes))
	}
}

func TestMarshalToJSON_IsCompact(t *testing.T) {
	time1 := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	vuln := &osvschema.Vulnerability{
		SchemaVersion: "1.6.0",
		Id:            "OSV-2026-1234",
		Modified:      timestamppb.New(time1),
		Published:     timestamppb.New(time1),
		Summary:       "A test vulnerability summary",
		Details:       "Detailed description with some text\nand a newline inside the string field.",
		Affected: []*osvschema.Affected{
			{
				Package: &osvschema.Package{
					Ecosystem: "PyPI",
					Name:      "test-pkg",
				},
				Ranges: []*osvschema.Range{
					{
						Type: osvschema.Range_ECOSYSTEM,
						Events: []*osvschema.Event{
							{Introduced: "0"},
							{Fixed: "1.0.0"},
						},
					},
				},
				DatabaseSpecific: &structpb.Struct{
					Fields: map[string]*structpb.Value{
						"custom_key": structpb.NewStringValue("custom_val"),
					},
				},
			},
		},
	}

	got, err := marshalToJSON(vuln)
	if err != nil {
		t.Fatalf("marshalToJSON failed: %v", err)
	}

	// Verify that the output is byte-for-byte identical to json.Compact
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, got); err != nil {
		t.Fatalf("json.Compact failed on marshalToJSON output: %v", err)
	}

	if !bytes.Equal(got, compacted.Bytes()) {
		t.Errorf("marshalToJSON output is not compact.\nGot:       %s\nCompacted: %s", string(got), compacted.String())
	}
}
