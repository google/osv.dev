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

// Package taskmsg builds Pub/Sub task messages consumed by the enrichment worker.
package taskmsg

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/osv.dev/go/logger"
	"github.com/klauspost/compress/zstd"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
)

// MaxPubSubMessageSize is the maximum compressed payload size included inline in a Pub/Sub task message.
const MaxPubSubMessageSize = 10_000_000

// UpdateParams holds the attributes and optional raw JSON payload for a worker "update" task message.
type UpdateParams struct {
	Source         string
	Path           string
	OriginalSHA256 string
	Deleted        bool
	WorkPool       string
	SrcTimestamp   *time.Time
	GitCommit      string
	GCSGeneration  *int64
	RawJSON        []byte
}

// NewUpdateMessage constructs a Pub/Sub "update" message with optional zstd-compressed
// raw JSON (omitted if compressed size exceeds MaxPubSubMessageSize) and injects OTel trace context.
func NewUpdateMessage(ctx context.Context, params UpdateParams) *pubsub.Message {
	var data []byte
	contentEncoding := ""
	if len(params.RawJSON) > 0 {
		// Make sure we have enough capacity for the compressed data to avoid reallocations.
		buf := make([]byte, 0, len(params.RawJSON))
		data = zstd.EncodeTo(buf, params.RawJSON)
		contentEncoding = "zstd"
		if len(data) > MaxPubSubMessageSize {
			logger.WarnContext(ctx, "Vulnerability JSON is too large",
				slog.String("source", params.Source),
				slog.String("path", params.Path),
				slog.Int("size", len(data)))

			// Set data to nil and let the worker decide what to do about it.
			data = nil
			contentEncoding = ""
		}
	}

	msg := &pubsub.Message{
		Data: data,
		Attributes: map[string]string{
			"type":             "update",
			"source":           params.Source,
			"path":             params.Path,
			"original_sha256":  params.OriginalSHA256,
			"deleted":          strconv.FormatBool(params.Deleted),
			"req_timestamp":    strconv.FormatInt(time.Now().Unix(), 10),
			"content_encoding": contentEncoding,
			"format":           "json",
			"work_pool":        params.WorkPool,
		},
	}
	if params.GitCommit != "" {
		msg.Attributes["git_commit"] = params.GitCommit
	}
	if params.GCSGeneration != nil {
		msg.Attributes["gcs_generation"] = strconv.FormatInt(*params.GCSGeneration, 10)
	}
	if params.SrcTimestamp != nil {
		msg.Attributes["src_timestamp"] = strconv.FormatInt(params.SrcTimestamp.Unix(), 10)
	} else {
		msg.Attributes["src_timestamp"] = ""
	}

	// Inject the current trace into the message.
	otel.GetTextMapPropagator().Inject(ctx, propagation.MapCarrier(msg.Attributes))

	return msg
}
