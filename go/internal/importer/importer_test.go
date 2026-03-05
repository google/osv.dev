package importer

import (
	"context"
	"testing"
	"time"

	"github.com/google/osv.dev/go/testutils"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestSendToWorker(t *testing.T) {
	mockPublisher := &testutils.MockPublisher{}
	config := Config{
		Publisher: mockPublisher,
	}
	ctx := context.Background()
	item := WorkItem{
		SourceRepository: "test-repo",
		SourcePath:       "test-path.json",
		IsReimport:       false,
	}
	hash := "some-hash"
	modifiedTime := time.Date(2023, 1, 1, 0, 0, 0, 0, time.UTC)
	vuln := &osvschema.Vulnerability{
		Id:       "CVE-2023-1234",
		Modified: timestamppb.New(modifiedTime),
	}

	err := sendToWorker(ctx, config, item, hash, modifiedTime, vuln)
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
	if len(msg.Data) == 0 {
		t.Errorf("Expected vulnerability data to be present")
	}
	var parsedVuln osvschema.Vulnerability
	if err := proto.Unmarshal(msg.Data, &parsedVuln); err != nil {
		t.Errorf("Failed to unmarshal vulnerability: %v", err)
	}
	if parsedVuln.GetId() != "CVE-2023-1234" {
		t.Errorf("Expected vulnerability ID CVE-2023-1234, got %s", parsedVuln.GetId())
	}
	if parsedVuln.GetModified().AsTime() != modifiedTime {
		t.Errorf("Expected vulnerability modified time %v, got %v", modifiedTime, parsedVuln.GetModified().AsTime())
	}
}

func TestImporterWorker(t *testing.T) {
	mockPublisher := &testutils.MockPublisher{}
	config := Config{
		Publisher: mockPublisher,
	}
	ctx := t.Context()
	ch := make(chan WorkItem, 10)

	// Test 1: JSON format
	ch <- WorkItem{
		Context: ctx,
		SourceRecord: mockSourceRecord{
			DataToRead: []byte(`{"id": "CVE-2023-1234", "modified": "2023-01-01T00:00:00Z"}`),
		},
		Format:           RecordFormatJSON,
		SourceRepository: "repo1",
		SourcePath:       "1.json",
	}

	// Test 2: YAML format
	ch <- WorkItem{
		Context: ctx,
		SourceRecord: mockSourceRecord{
			DataToRead: []byte("id: CVE-2023-1235\nmodified: 2023-01-02T00:00:00Z\n"),
		},
		Format:           RecordFormatYAML,
		SourceRepository: "repo2",
		SourcePath:       "2.yaml",
	}

	// Test 3: KeyPath extraction
	ch <- WorkItem{
		Context: ctx,
		SourceRecord: mockSourceRecord{
			DataToRead: []byte(`{"data": {"id": "CVE-2023-1236", "modified": "2023-01-03T00:00:00Z"}}`),
		},
		Format:           RecordFormatJSON,
		KeyPath:          "data",
		SourceRepository: "repo3",
		SourcePath:       "3.json",
	}

	// Test 4: Skip older record
	ch <- WorkItem{
		Context: ctx,
		SourceRecord: mockSourceRecord{
			DataToRead: []byte(`{"id": "CVE-2023-1237", "modified": "2023-01-04T00:00:00Z"}`),
		},
		Format:           RecordFormatJSON,
		LastUpdated:      time.Date(2023, 1, 5, 0, 0, 0, 0, time.UTC),
		HasLastUpdated:   true,
		SourceRepository: "repo4",
		SourcePath:       "4.json",
	}
	close(ch)

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
