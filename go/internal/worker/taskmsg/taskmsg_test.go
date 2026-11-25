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

package taskmsg

import (
	"context"
	"testing"
	"time"

	"github.com/klauspost/compress/zstd"
)

func TestNewUpdateMessage(t *testing.T) {
	ctx := context.Background()
	srcTime := time.Date(2026, 4, 1, 12, 0, 0, 0, time.UTC)
	gen := int64(42)
	rawJSON := []byte(`{"id":"OSV-2026-1"}`)

	msg := NewUpdateMessage(ctx, UpdateParams{
		Source:         "test-source",
		Path:           "vulns/OSV-2026-1.json",
		OriginalSHA256: "deadbeef",
		Deleted:        false,
		WorkPool:       "default",
		SrcTimestamp:   &srcTime,
		GitCommit:      "abc123",
		GCSGeneration:  &gen,
		RawJSON:        rawJSON,
	})

	if msg.Attributes["type"] != "update" {
		t.Errorf("type = %q, want update", msg.Attributes["type"])
	}
	if msg.Attributes["source"] != "test-source" {
		t.Errorf("source = %q, want test-source", msg.Attributes["source"])
	}
	if msg.Attributes["path"] != "vulns/OSV-2026-1.json" {
		t.Errorf("path = %q, want vulns/OSV-2026-1.json", msg.Attributes["path"])
	}
	if msg.Attributes["original_sha256"] != "deadbeef" {
		t.Errorf("original_sha256 = %q, want deadbeef", msg.Attributes["original_sha256"])
	}
	if msg.Attributes["deleted"] != "false" {
		t.Errorf("deleted = %q, want false", msg.Attributes["deleted"])
	}
	if msg.Attributes["content_encoding"] != "zstd" {
		t.Errorf("content_encoding = %q, want zstd", msg.Attributes["content_encoding"])
	}
	if msg.Attributes["format"] != "json" {
		t.Errorf("format = %q, want json", msg.Attributes["format"])
	}
	if msg.Attributes["work_pool"] != "default" {
		t.Errorf("work_pool = %q, want default", msg.Attributes["work_pool"])
	}
	if msg.Attributes["git_commit"] != "abc123" {
		t.Errorf("git_commit = %q, want abc123", msg.Attributes["git_commit"])
	}
	if msg.Attributes["gcs_generation"] != "42" {
		t.Errorf("gcs_generation = %q, want 42", msg.Attributes["gcs_generation"])
	}
	if msg.Attributes["src_timestamp"] != "1775044800" {
		t.Errorf("src_timestamp = %q, want 1775044800", msg.Attributes["src_timestamp"])
	}
	if msg.Attributes["req_timestamp"] == "" {
		t.Errorf("req_timestamp is empty")
	}

	decoded, err := zstd.DecodeTo(nil, msg.Data)
	if err != nil {
		t.Fatalf("zstd.DecodeTo: %v", err)
	}
	if string(decoded) != string(rawJSON) {
		t.Errorf("decoded = %q, want %q", decoded, rawJSON)
	}
}

func TestNewUpdateMessage_Deletion(t *testing.T) {
	msg := NewUpdateMessage(context.Background(), UpdateParams{
		Source:   "test-source",
		Path:     "vulns/OSV-2026-1.json",
		Deleted:  true,
		WorkPool: "reimport",
	})

	if msg.Attributes["deleted"] != "true" {
		t.Errorf("deleted = %q, want true", msg.Attributes["deleted"])
	}
	if msg.Attributes["content_encoding"] != "" {
		t.Errorf("content_encoding = %q, want empty", msg.Attributes["content_encoding"])
	}
	if msg.Attributes["src_timestamp"] != "" {
		t.Errorf("src_timestamp = %q, want empty", msg.Attributes["src_timestamp"])
	}
	if _, ok := msg.Attributes["git_commit"]; ok {
		t.Errorf("git_commit should be omitted when empty")
	}
	if _, ok := msg.Attributes["gcs_generation"]; ok {
		t.Errorf("gcs_generation should be omitted when nil")
	}
	if len(msg.Data) != 0 {
		t.Errorf("len(Data) = %d, want 0", len(msg.Data))
	}
}
