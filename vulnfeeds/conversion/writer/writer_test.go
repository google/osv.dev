package writer

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fsouza/fake-gcs-server/fakestorage"
	gcs "github.com/google/osv/vulnfeeds/gcs-tools"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestWriteToDisk(t *testing.T) {
	tempDir := t.TempDir()
	v := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
	}
	preModifiedBuf := []byte(`{"id":"CVE-2023-1234"}`)

	err := writeToDisk(v, preModifiedBuf, tempDir)
	if err != nil {
		t.Errorf("Expected writeToDisk to return nil, got %v", err)
	}

	filePath := path.Join(tempDir, "CVE-2023-1234.json")
	content, err := os.ReadFile(filePath)
	if err != nil {
		t.Fatalf("Failed to read written file: %v", err)
	}

	if !bytes.Equal(content, preModifiedBuf) {
		t.Errorf("Expected content %s, got %s", preModifiedBuf, content)
	}
}

func TestUploadToGCS(t *testing.T) {
	server := fakestorage.NewServer([]fakestorage.Object{})
	defer server.Stop()
	client := server.Client()
	ctx := context.Background()

	bucketName := "test-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: bucketName})
	bkt := client.Bucket(bucketName)

	v := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
	}
	preModifiedBuf := []byte(`{"id":"CVE-2023-1234"}`)

	t.Run("Upload new object", func(t *testing.T) {
		hash := sha256.Sum256(preModifiedBuf)
		hexHash := hex.EncodeToString(hash[:])
		err := uploadIfChanged(ctx, v, hexHash, preModifiedBuf, bkt, "")
		if err != nil {
			t.Errorf("Expected uploadToGCS to return nil for new object, got %v", err)
		}

		obj := bkt.Object("CVE-2023-1234.json")
		attrs, err := obj.Attrs(ctx)
		if err != nil {
			t.Fatalf("Failed to get object attrs: %v", err)
		}

		if attrs.Metadata[hashMetadataKey] != hexHash {
			t.Errorf("Expected hash %s, got %s", hexHash, attrs.Metadata[hashMetadataKey])
		}
	})

	t.Run("Skip upload if hash matches", func(t *testing.T) {
		// Modify the vulnerability to simulate a change in modified time but not content
		v.Modified = timestamppb.New(time.Now().Add(1 * time.Hour))
		hash := sha256.Sum256(preModifiedBuf)
		hexHash := hex.EncodeToString(hash[:])
		err := uploadIfChanged(ctx, v, hexHash, preModifiedBuf, bkt, "")
		if !errors.Is(err, ErrUploadSkipped) {
			t.Errorf("Expected uploadToGCS to return ErrUploadSkipped when hash matches, got %v", err)
		}

		obj := bkt.Object("CVE-2023-1234.json")
		attrs2, err := obj.Attrs(ctx)
		if err != nil {
			t.Fatalf("Failed to get object attrs: %v", err)
		}

		// We need to fetch the original attrs to compare Updated time
		attrs1, _ := obj.Attrs(ctx)
		if attrs1.Updated != attrs2.Updated {
			t.Errorf("Expected object not to be updated, but it was")
		}
	})

	t.Run("Upload if hash differs", func(t *testing.T) {
		preModifiedBuf2 := []byte(`{"id":"CVE-2023-1234", "summary": "updated"}`)
		hash2 := sha256.Sum256(preModifiedBuf2)
		hexHash2 := hex.EncodeToString(hash2[:])
		err := uploadIfChanged(ctx, v, hexHash2, preModifiedBuf2, bkt, "")
		if err != nil {
			t.Errorf("Expected uploadToGCS to return nil when hash differs, got %v", err)
		}

		obj := bkt.Object("CVE-2023-1234.json")
		attrs3, err := obj.Attrs(ctx)
		if err != nil {
			t.Fatalf("Failed to get object attrs: %v", err)
		}

		if attrs3.Metadata[hashMetadataKey] != hexHash2 {
			t.Errorf("Expected hash %s, got %s", hexHash2, attrs3.Metadata[hashMetadataKey])
		}
	})
}

func TestHandleOverride(t *testing.T) {
	server := fakestorage.NewServer([]fakestorage.Object{})
	defer server.Stop()
	client := server.Client()
	ctx := context.Background()

	bucketName := "test-overrides-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: bucketName})
	bkt := client.Bucket(bucketName)

	v := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
	}

	t.Run("No override", func(t *testing.T) {
		outV, outBuf, err := handleOverride(ctx, v, bkt)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if outV != v {
			t.Errorf("Expected original vulnerability, got different one")
		}
		if outBuf != nil {
			t.Errorf("Expected nil buffer, got %s", outBuf)
		}
	})

	t.Run("Override exists", func(t *testing.T) {
		overrideV := &osvschema.Vulnerability{
			Id:      "CVE-2023-1234",
			Summary: "Overridden summary",
		}
		overrideBuf, _ := json.Marshal(overrideV)

		obj := bkt.Object(path.Join(overrideFolder, "CVE-2023-1234.json"))
		w := obj.NewWriter(ctx)
		if _, err := w.Write(overrideBuf); err != nil {
			t.Fatalf("Failed to write override object: %v", err)
		}
		w.Close()

		outV2, outBuf2, err := handleOverride(ctx, v, bkt)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if outV2.GetSummary() != "Overridden summary" {
			t.Errorf("Expected overridden summary, got %s", outV2.GetSummary())
		}
		if !bytes.Equal(outBuf2, overrideBuf) {
			t.Errorf("Expected buffer %s, got %s", overrideBuf, outBuf2)
		}
	})

	t.Run("Override exists with published field", func(t *testing.T) {
		overrideJSON := []byte(`{"id": "CVE-2023-1234", "summary": "Overridden summary", "published": "2023-01-01T00:00:00Z"}`)

		obj := bkt.Object(path.Join(overrideFolder, "CVE-2023-1234.json"))
		w := obj.NewWriter(ctx)
		if _, err := w.Write(overrideJSON); err != nil {
			t.Fatalf("Failed to write override object: %v", err)
		}
		w.Close()

		outV3, outBuf3, err := handleOverride(ctx, v, bkt)
		if err != nil {
			t.Fatalf("Unexpected error: %v", err)
		}
		if outV3.GetSummary() != "Overridden summary" {
			t.Errorf("Expected overridden summary, got %s", outV3.GetSummary())
		}
		if !bytes.Equal(outBuf3, overrideJSON) {
			t.Errorf("Expected buffer %s, got %s", overrideJSON, outBuf3)
		}
	})
}

func TestWorker(t *testing.T) {
	server := fakestorage.NewServer([]fakestorage.Object{})
	defer server.Stop()
	client := server.Client()
	ctx := context.Background()

	outBucketName := "test-out-bucket"
	overridesBucketName := "test-overrides-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: outBucketName})
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: overridesBucketName})
	outBkt := client.Bucket(outBucketName)
	overridesBkt := client.Bucket(overridesBucketName)

	vulnChan := make(chan *osvschema.Vulnerability, 2)
	v1 := &osvschema.Vulnerability{
		Id: "CVE-2023-1234",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Name: "pkg1"}},
		},
	}
	v2 := &osvschema.Vulnerability{
		Id: "CVE-2023-5678",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Name: "pkg2"}},
		},
	}
	vulnChan <- v1
	vulnChan <- v2
	close(vulnChan)

	// Add an override for v2
	overrideV2 := &osvschema.Vulnerability{
		Id:      "CVE-2023-5678",
		Summary: "Overridden summary",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Name: "pkg2"}},
		},
	}
	overrideBuf, _ := protojson.Marshal(overrideV2)
	obj := overridesBkt.Object(path.Join(overrideFolder, "CVE-2023-5678.json"))
	w := obj.NewWriter(ctx)
	if _, err := w.Write(overrideBuf); err != nil {
		t.Fatalf("Failed to write override object: %v", err)
	}
	w.Close()

	var counter atomic.Uint64
	VulnWorker(ctx, vulnChan, outBkt, overridesBkt, nil, "", &counter)

	if counter.Load() != 2 {
		t.Errorf("Expected counter to be 2, got %d", counter.Load())
	}

	// Check v1
	obj1 := outBkt.Object("CVE-2023-1234.json")
	_, err := obj1.Attrs(ctx)
	if err != nil {
		t.Errorf("Expected v1 to be uploaded, but got error: %v", err)
	}

	// Check v2
	obj2 := outBkt.Object("CVE-2023-5678.json")
	r, err := obj2.NewReader(ctx)
	if err != nil {
		t.Fatalf("Expected v2 to be uploaded, but got error: %v", err)
	}
	defer r.Close()
	content, _ := io.ReadAll(r)
	var uploadedV2 osvschema.Vulnerability
	if err := protojson.Unmarshal(content, &uploadedV2); err != nil {
		t.Fatalf("Failed to unmarshal uploaded v2: %v", err)
	}
	if uploadedV2.GetSummary() != "Overridden summary" {
		t.Errorf("Expected v2 to have overridden summary, got %s", uploadedV2.GetSummary())
	}
}

func TestUpload(t *testing.T) {
	server, err := fakestorage.NewServerWithOptions(fakestorage.Options{
		Scheme: "http",
	})
	if err != nil {
		t.Fatalf("Failed to create fake storage server: %v", err)
	}
	defer server.Stop()

	t.Setenv("STORAGE_EMULATOR_HOST", server.URL())

	ctx := context.Background()

	outBucketName := "test-out-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: outBucketName})

	vulnerabilities := []*osvschema.Vulnerability{
		{
			Id: "CVE-2023-1234",
			Affected: []*osvschema.Affected{
				{Package: &osvschema.Package{Name: "pkg1"}},
			},
		},
	}

	UploadVulnsToGCS(ctx, "test-job", true, outBucketName, "", 1, "", vulnerabilities, false)

	client := server.Client()
	bkt := client.Bucket(outBucketName)
	_, err = bkt.Object("CVE-2023-1234.json").Attrs(ctx)
	if err != nil {
		t.Errorf("Expected object to be uploaded, but got error: %v", err)
	}
}

func TestHandleDeletion(t *testing.T) {
	server := fakestorage.NewServer([]fakestorage.Object{})
	defer server.Stop()
	client := server.Client()
	ctx := context.Background()

	bucketName := "test-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: bucketName})
	bkt := client.Bucket(bucketName)

	// Create some existing objects
	w1 := bkt.Object("CVE-2023-1111.json").NewWriter(ctx)
	if _, err := w1.Write([]byte("{}")); err != nil {
		t.Fatalf("Failed to write object: %v", err)
	}
	w1.Close()

	w2 := bkt.Object("CVE-2023-2222.json").NewWriter(ctx)
	if _, err := w2.Write([]byte("{}")); err != nil {
		t.Fatalf("Failed to write object: %v", err)
	}
	w2.Close()

	vulnerabilities := []*osvschema.Vulnerability{
		{Id: "CVE-2023-1111"},
		{Id: "CVE-2023-3333"},
	}

	HandleDeletion(ctx, bkt, "", vulnerabilities)

	// CVE-2023-1111.json should still exist
	if _, err := bkt.Object("CVE-2023-1111.json").Attrs(ctx); err != nil {
		t.Errorf("Expected CVE-2023-1111.json to exist, but got error: %v", err)
	}

	// CVE-2023-2222.json should be deleted
	if _, err := bkt.Object("CVE-2023-2222.json").Attrs(ctx); err == nil {
		t.Errorf("Expected CVE-2023-2222.json to be deleted, but it still exists")
	}
}

func TestUploadVulnIfChangedAsync(t *testing.T) {
	server, err := fakestorage.NewServerWithOptions(fakestorage.Options{
		Scheme: "http",
	})
	if err != nil {
		t.Fatalf("Failed to create fake storage server: %v", err)
	}
	defer server.Stop()

	t.Setenv("STORAGE_EMULATOR_HOST", server.URL())

	ctx := context.Background()
	bucketName := "test-out-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: bucketName})

	gcsHelper, err := gcs.InitUploadPool(ctx, 2, bucketName)
	if err != nil {
		t.Fatalf("Failed to init upload pool: %v", err)
	}

	v := &osvschema.Vulnerability{
		Id: "CVE-2023-9999",
		Affected: []*osvschema.Affected{
			{Package: &osvschema.Package{Name: "test-pkg"}},
		},
	}

	t.Run("Async upload new object", func(t *testing.T) {
		err := UploadVulnIfChangedAsync(gcsHelper, "nvd-prefix", v)
		if err != nil {
			t.Fatalf("Expected UploadVulnIfChangedAsync to succeed, got %v", err)
		}

		gcsHelper.CloseAndWait()

		client := server.Client()
		bkt := client.Bucket(bucketName)
		objName := "nvd-prefix/CVE-2023-9999.json"
		obj := bkt.Object(objName)
		attrs, err := obj.Attrs(ctx)
		if err != nil {
			t.Fatalf("Expected object %q to exist on GCS, got error: %v", objName, err)
		}

		if attrs.Metadata[hashMetadataKey] == "" {
			t.Errorf("Expected hash metadata to be set on GCS object")
		}
	})
}

func TestUploadMetricsToGCSAsync(t *testing.T) {
	server, err := fakestorage.NewServerWithOptions(fakestorage.Options{
		Scheme: "http",
	})
	if err != nil {
		t.Fatalf("Failed to create fake storage server: %v", err)
	}
	defer server.Stop()

	t.Setenv("STORAGE_EMULATOR_HOST", server.URL())

	ctx := context.Background()
	bucketName := "test-out-bucket"
	server.CreateBucketWithOpts(fakestorage.CreateBucketOpts{Name: bucketName})

	gcsHelper, err := gcs.InitUploadPool(ctx, 2, bucketName)
	if err != nil {
		t.Fatalf("Failed to init upload pool: %v", err)
	}

	metrics := &models.ConversionMetrics{
		CVEID: "CVE-2023-9999",
		CNA:   "nvd",
	}

	err = UploadMetricsToGCSAsync(gcsHelper, "nvd-prefix", "CVE-2023-9999", metrics)
	if err != nil {
		t.Fatalf("Expected UploadMetricsToGCSAsync to succeed, got %v", err)
	}

	gcsHelper.CloseAndWait()

	client := server.Client()
	bkt := client.Bucket(bucketName)
	objName := "nvd-prefix/CVE-2023-9999.metrics.json"
	_, err = bkt.Object(objName).Attrs(ctx)
	if err != nil {
		t.Fatalf("Expected metrics object %q to exist on GCS, got error: %v", objName, err)
	}
}
