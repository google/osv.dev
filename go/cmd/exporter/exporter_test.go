package main

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
	storage := testutils.NewMockStorage()

	inCh := make(chan *osvschema.Vulnerability, 10)
	routerToWriteCh := make(chan writeMsg, 100)

	var writerWg sync.WaitGroup
	writerWg.Add(1)
	go writer(ctx, cancel, routerToWriteCh, storage, "export", &writerWg)

	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, inCh, routerToWriteCh, scratchDir, &routerWg)

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

	inCh <- vuln1
	inCh <- vuln2
	close(inCh)

	routerWg.Wait()
	close(routerToWriteCh)
	writerWg.Wait()

	// 1. Verify individual JSON outputs
	pypiJSON, err := storage.ReadObject(ctx, "export/PyPI/GHSA-pypi-1.json")
	if err != nil {
		t.Fatalf("expected PyPI/GHSA-pypi-1.json in storage: %v", err)
	}
	if !bytes.Contains(pypiJSON, []byte(`"id":"GHSA-pypi-1"`)) {
		t.Errorf("PyPI JSON content mismatch: %s", string(pypiJSON))
	}

	npmJSON, err := storage.ReadObject(ctx, "export/npm/GHSA-npm-git-2.json")
	if err != nil {
		t.Fatalf("expected npm/GHSA-npm-git-2.json in storage: %v", err)
	}
	if !bytes.Contains(npmJSON, []byte(`"id":"GHSA-npm-git-2"`)) {
		t.Errorf("npm JSON content mismatch: %s", string(npmJSON))
	}

	// 2. Verify all.zip contains all JSON files
	allZipBytes, err := storage.ReadObject(ctx, "export/all.zip")
	if err != nil {
		t.Fatalf("expected all.zip: %v", err)
	}
	zipReader, err := zip.NewReader(bytes.NewReader(allZipBytes), int64(len(allZipBytes)))
	if err != nil {
		t.Fatalf("failed to open all.zip: %v", err)
	}
	var zipNames []string
	for _, f := range zipReader.File {
		zipNames = append(zipNames, f.Name)
	}
	if len(zipNames) != 2 {
		t.Errorf("expected 2 files in all.zip, got %v", zipNames)
	}

	// 3. Verify modified_id.csv ordering (descending by modified time)
	csvBytes, err := storage.ReadObject(ctx, "export/modified_id.csv")
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
	ecoTxtBytes, err := storage.ReadObject(ctx, "export/ecosystems.txt")
	if err != nil {
		t.Fatalf("expected ecosystems.txt: %v", err)
	}
	expectedEco := "GIT\nPyPI\nnpm\n"
	if string(ecoTxtBytes) != expectedEco {
		t.Errorf("expected %q in ecosystems.txt, got %q", expectedEco, string(ecoTxtBytes))
	}

	// 5. Verify Vanir signatures file (GIT/osv_git.json)
	vanirBytes, err := storage.ReadObject(ctx, "export/GIT/osv_git.json")
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
