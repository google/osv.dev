package worker

import (
	"testing"

	"cloud.google.com/go/pubsub/v2"
	"github.com/klauspost/compress/zstd"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

func TestParseVuln_JSON(t *testing.T) {
	sub := &Subscriber{}
	rawJSON := []byte(`{"id":"OSV-2026-1","summary":"test summary","unknown_field":"ignored"}`)

	t.Run("uncompressed json with format attribute", func(t *testing.T) {
		msg := &pubsub.Message{
			Data: rawJSON,
			Attributes: map[string]string{
				"format": "json",
			},
		}
		v, gotJSON, err := sub.parseVuln(msg)
		if err != nil {
			t.Fatalf("parseVuln() error = %v", err)
		}
		if v.GetId() != "OSV-2026-1" || v.GetSummary() != "test summary" {
			t.Errorf("parseVuln() vuln = %+v", v)
		}
		if string(gotJSON) != string(rawJSON) {
			t.Errorf("parseVuln() rawJSON = %q, want %q", gotJSON, rawJSON)
		}
	})

	t.Run("zstd-compressed json", func(t *testing.T) {
		enc, err := zstd.NewWriter(nil)
		if err != nil {
			t.Fatalf("zstd.NewWriter: %v", err)
		}
		compressed := enc.EncodeAll(rawJSON, nil)
		_ = enc.Close()

		msg := &pubsub.Message{
			Data: compressed,
			Attributes: map[string]string{
				"content_encoding": "zstd",
				"format":           "json",
			},
		}
		v, gotJSON, err := sub.parseVuln(msg)
		if err != nil {
			t.Fatalf("parseVuln() error = %v", err)
		}
		if v.GetId() != "OSV-2026-1" {
			t.Errorf("parseVuln() id = %q, want OSV-2026-1", v.GetId())
		}
		if string(gotJSON) != string(rawJSON) {
			t.Errorf("parseVuln() rawJSON = %q, want %q", gotJSON, rawJSON)
		}
	})

	t.Run("legacy protobuf fallback", func(t *testing.T) {
		orig := &osvschema.Vulnerability{
			Id:      "OSV-2026-2",
			Summary: "proto summary",
		}
		pbData, err := proto.Marshal(orig)
		if err != nil {
			t.Fatalf("proto.Marshal: %v", err)
		}
		msg := &pubsub.Message{
			Data: pbData,
		}
		v, gotJSON, err := sub.parseVuln(msg)
		if err != nil {
			t.Fatalf("parseVuln() error = %v", err)
		}
		if v.GetId() != "OSV-2026-2" || v.GetSummary() != "proto summary" {
			t.Errorf("parseVuln() vuln = %+v", v)
		}
		if gotJSON != nil {
			t.Errorf("parseVuln() rawJSON = %q, want nil for protobuf message", gotJSON)
		}
	})
}
