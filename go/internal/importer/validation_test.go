package importer

import (
	"context"
	"testing"

	"github.com/google/osv.dev/go/testutils"
)

func TestImporterWorker_StrictValidation(t *testing.T) {
	mockPublisher := &testutils.MockPublisher{}
	config := Config{
		Publisher:        mockPublisher,
		StrictValidation: true,
	}

	tests := []struct {
		name        string
		data        string
		format      RecordFormat
		wantPublish bool
	}{
		{
			name:        "Valid record",
			data:        `{"id": "OSV-2023-123", "modified": "2023-01-01T00:00:00Z"}`,
			format:      RecordFormatJSON,
			wantPublish: true,
		},
		{
			name:        "Invalid record (missing modified)",
			data:        `{"id": "OSV-2023-124"}`,
			format:      RecordFormatJSON,
			wantPublish: false,
		},
		{
			name:        "Invalid record (unknown field with strict config)",
			data:        `{"id": "OSV-2023-125", "modified": "2023-01-01T00:00:00Z", "unknown": "field"}`,
			format:      RecordFormatJSON,
			wantPublish: false,
		},
		{
			name:        "Invalid record (source-specific strictness)",
			data:        `{"id": "OSV-2023-126", "modified": "2023-01-01T00:00:00Z", "unknown": "field"}`,
			format:      RecordFormatJSON,
			wantPublish: false,
		},
		{
			name:        "Valid yaml record",
			data:        "id: OSV-2023-127\nmodified: 2023-01-01T00:00:00Z",
			format:      RecordFormatYAML,
			wantPublish: true,
		},
		{
			name:        "Invalid yaml record",
			data:        "id: OSV-2023-128\nmodified: 2023-01-01T00:00:00Z\nunknown: field",
			format:      RecordFormatYAML,
			wantPublish: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockPublisher.Messages = nil // Reset

			ch := make(chan WorkItem, 1)
			record := mockSourceRecord{
				DataToRead: []byte(tt.data),
			}
			ch <- WorkItem{
				Context:      t.Context(),
				SourceRecord: record,
				Strict:       true,
				Format:       tt.format,
			}
			close(ch)

			importerWorker(t.Context(), ch, config)

			if tt.wantPublish && len(mockPublisher.Messages) == 0 {
				t.Errorf("Expected message to be published, but wasn't")
			}
			if !tt.wantPublish && len(mockPublisher.Messages) > 0 {
				t.Errorf("Expected no message to be published, but got %d", len(mockPublisher.Messages))
			}
		})
	}
}

func TestImporterWorker_NonStrictResilience(t *testing.T) {
	mockPublisher := &testutils.MockPublisher{}
	config := Config{
		Publisher:        mockPublisher,
		StrictValidation: false,
	}

	// Unknown fields should be ignored when non-strict
	data := `{"id": "OSV-2023-127", "modified": "2023-01-01T00:00:00Z", "unknown_field": "resilience"}`
	record := mockSourceRecord{
		DataToRead: []byte(data),
	}

	ctx, cancel := context.WithCancel(t.Context())
	ch := make(chan WorkItem, 1)
	ch <- WorkItem{
		Context:      ctx,
		SourceRecord: record,
		Format:       RecordFormatJSON,
	}
	close(ch)

	importerWorker(ctx, ch, config)
	cancel()

	if len(mockPublisher.Messages) != 1 {
		t.Errorf("Expected message to be published (ignoring unknown field), but got %d", len(mockPublisher.Messages))
	}
}
