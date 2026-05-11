package main

import (
	"context"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/osv.dev/go/osv/clients"
	"github.com/google/osv.dev/go/testutils"
)

// runWriter sends msgs to a writer goroutine and waits for it to finish.
func runWriter(t *testing.T, storage clients.CloudStorage, pathPrefix string, msgs []writeMsg) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	inCh := make(chan writeMsg, len(msgs))
	for _, m := range msgs {
		inCh <- m
	}
	close(inCh)

	var wg sync.WaitGroup
	wg.Add(1)
	go writer(ctx, cancel, inCh, storage, pathPrefix, &wg)
	wg.Wait()
}

func TestWriter_GCS_SkipsUnchangedContent(t *testing.T) {
	storage := testutils.NewMockStorage()
	data := []byte(`{"id":"OSV-1"}`)

	// Pre-populate using the same path the writer will compute.
	objPath := filepath.Join("out", "OSV-1.json")
	if err := storage.WriteObject(t.Context(), objPath, data, nil); err != nil {
		t.Fatalf("setup: %v", err)
	}
	attrsBefore, _ := storage.ReadObjectAttrs(t.Context(), objPath)

	runWriter(t, storage, "out", []writeMsg{
		{path: "OSV-1.json", mimeType: "application/json", data: data},
	})

	attrsAfter, err := storage.ReadObjectAttrs(t.Context(), objPath)
	if err != nil {
		t.Fatalf("ReadObjectAttrs: %v", err)
	}
	if attrsAfter.Generation != attrsBefore.Generation {
		t.Errorf("expected generation %d (skipped), got %d", attrsBefore.Generation, attrsAfter.Generation)
	}
}

func TestWriter_GCS_UploadsChangedContent(t *testing.T) {
	storage := testutils.NewMockStorage()

	objPath := filepath.Join("out", "OSV-1.json")
	if err := storage.WriteObject(t.Context(), objPath, []byte(`{"id":"OSV-1","old":true}`), nil); err != nil {
		t.Fatalf("setup: %v", err)
	}
	attrsBefore, _ := storage.ReadObjectAttrs(t.Context(), objPath)

	runWriter(t, storage, "out", []writeMsg{
		{path: "OSV-1.json", mimeType: "application/json", data: []byte(`{"id":"OSV-1","old":false}`)},
	})

	attrsAfter, err := storage.ReadObjectAttrs(t.Context(), objPath)
	if err != nil {
		t.Fatalf("ReadObjectAttrs: %v", err)
	}
	if attrsAfter.Generation <= attrsBefore.Generation {
		t.Errorf("expected generation > %d (uploaded), got %d", attrsBefore.Generation, attrsAfter.Generation)
	}
}

func TestWriter_GCS_UploadsNewObject(t *testing.T) {
	storage := testutils.NewMockStorage()

	runWriter(t, storage, "out", []writeMsg{
		{path: "OSV-1.json", mimeType: "application/json", data: []byte(`{"id":"OSV-1"}`)},
	})

	objPath := filepath.Join("out", "OSV-1.json")
	attrs, err := storage.ReadObjectAttrs(t.Context(), objPath)
	if err != nil {
		t.Fatalf("expected object to exist after upload: %v", err)
	}
	if attrs.Generation != 1 {
		t.Errorf("expected generation 1 for new object, got %d", attrs.Generation)
	}
}

func TestWriter_GCS_SkipsMultipleUnchanged(t *testing.T) {
	storage := testutils.NewMockStorage()

	type entry struct {
		msgPath string
		objPath string
		data    []byte
	}
	entries := []entry{
		{"A.json", filepath.Join("out", "A.json"), []byte(`{"id":"A"}`)},
		{"B.json", filepath.Join("out", "B.json"), []byte(`{"id":"B"}`)},
		{"C.json", filepath.Join("out", "C.json"), []byte(`{"id":"C"}`)},
	}
	for _, e := range entries {
		if err := storage.WriteObject(t.Context(), e.objPath, e.data, nil); err != nil {
			t.Fatalf("setup %s: %v", e.objPath, err)
		}
	}

	gensBefore := make(map[string]int64)
	for _, e := range entries {
		attrs, _ := storage.ReadObjectAttrs(t.Context(), e.objPath)
		gensBefore[e.objPath] = attrs.Generation
	}

	msgs := make([]writeMsg, len(entries))
	for i, e := range entries {
		msgs[i] = writeMsg{path: e.msgPath, mimeType: "application/json", data: e.data}
	}
	runWriter(t, storage, "out", msgs)

	for _, e := range entries {
		attrs, err := storage.ReadObjectAttrs(t.Context(), e.objPath)
		if err != nil {
			t.Fatalf("ReadObjectAttrs(%s): %v", e.objPath, err)
		}
		if attrs.Generation != gensBefore[e.objPath] {
			t.Errorf("%s: expected generation %d (skipped), got %d", e.objPath, gensBefore[e.objPath], attrs.Generation)
		}
	}
}
