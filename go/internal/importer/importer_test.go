package importer

import (
	"context"
	"testing"
	"time"

	"github.com/google/osv.dev/go/testutils"
)

func TestSendToWorker(t *testing.T) {
	mockPublisher := &testutils.MockPublisher{}
	config := Config{
		Publisher: mockPublisher,
	}
	ctx := context.Background()
	mockRecord := mockSourceRecord{
		MockSourceRepository: "test-repo",
		MockSourcePath:       "test-path.json",
		MockSendModifiedTime: true,
	}
	hash := "some-hash"
	modifiedTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)

	err := sendToWorker(ctx, config, mockRecord, hash, modifiedTime)
	if err != nil {
		t.Errorf("Expected no error, got %v", err)
	}

	if len(mockPublisher.Messages) != 1 {
		t.Fatalf("Expected 1 message published, got %d", len(mockPublisher.Messages))
	}

	msg := mockPublisher.Messages[0]
	if msg.Attributes["type"] != "update" {
		t.Errorf("Expected type=update, got %s", msg.Attributes["type"])
	}
	if msg.Attributes["source"] != "test-repo" {
		t.Errorf("Expected source=test-repo, got %s", msg.Attributes["source"])
	}
	if msg.Attributes["path"] != "test-path.json" {
		t.Errorf("Expected path=test-path.json, got %s", msg.Attributes["path"])
	}
	if msg.Attributes["original_sha256"] != "some-hash" {
		t.Errorf("Expected original_sha256=some-hash, got %s", msg.Attributes["original_sha256"])
	}
	if msg.Attributes["deleted"] != "false" {
		t.Errorf("Expected deleted=false, got %s", msg.Attributes["deleted"])
	}
	if msg.Attributes["req_timestamp"] == "" {
		t.Errorf("Expected req_timestamp to be set")
	}
	if msg.Attributes["src_timestamp"] != "1672531200" {
		t.Errorf("Expected src_timestamp=1672531200, got %s", msg.Attributes["src_timestamp"])
	}
}

func TestImporterWorker(t *testing.T) {
	mockPublisher := &testutils.MockPublisher{}
	config := Config{
		Publisher: mockPublisher,
	}
	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan SourceRecord, 10)

	// Test 1: JSON format
	ch <- mockSourceRecord{
		MockFormat:           RecordFormatJSON,
		DataToRead:           []byte(`{"id": "CVE-2023-1234", "modified": "2023-01-01T00:00:00Z"}`),
		MockSourceRepository: "repo1",
		MockSourcePath:       "1.json",
	}

	// Test 2: YAML format
	ch <- mockSourceRecord{
		MockFormat:           RecordFormatYAML,
		DataToRead:           []byte("id: CVE-2023-1235\nmodified: 2023-01-02T00:00:00Z\n"),
		MockSourceRepository: "repo2",
		MockSourcePath:       "2.yaml",
	}

	// Test 3: KeyPath extraction
	ch <- mockSourceRecord{
		MockFormat:           RecordFormatJSON,
		MockKeyPath:          "data",
		DataToRead:           []byte(`{"data": {"id": "CVE-2023-1236", "modified": "2023-01-03T00:00:00Z"}}`),
		MockSourceRepository: "repo3",
		MockSourcePath:       "3.json",
	}

	// Test 4: Skip older record
	ch <- mockSourceRecord{
		MockFormat:           RecordFormatJSON,
		DataToRead:           []byte(`{"id": "CVE-2023-1237", "modified": "2023-01-04T00:00:00Z"}`),
		MockLastUpdated:      time.Date(2023, 1, 5, 0, 0, 0, 0, time.UTC),
		MockHasUpdateTime:    true,
		MockSourceRepository: "repo4",
		MockSourcePath:       "4.json",
	}

	go func() {
		// Wait a bit and then close to unblock worker
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()

	importerWorker(ctx, ch, config)

	// Since Test 4 is skipped (modified before last update), we expect only 3 messages
	if len(mockPublisher.Messages) != 3 {
		t.Fatalf("Expected 3 messages published, got %d", len(mockPublisher.Messages))
	}

	// Message 1 verification
	if mockPublisher.Messages[0].Attributes["path"] != "1.json" {
		t.Errorf("Expected path 1.json, got %s", mockPublisher.Messages[0].Attributes["path"])
	}

	// Message 2 verification
	if mockPublisher.Messages[1].Attributes["path"] != "2.yaml" {
		t.Errorf("Expected path 2.yaml, got %s", mockPublisher.Messages[1].Attributes["path"])
	}

	// Message 3 verification
	if mockPublisher.Messages[2].Attributes["path"] != "3.json" {
		t.Errorf("Expected path 3.json, got %s", mockPublisher.Messages[2].Attributes["path"])
	}
}
