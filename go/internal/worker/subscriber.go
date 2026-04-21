package worker

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/osv.dev/go/logger"
	"github.com/klauspost/compress/zstd"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/protobuf/proto"
)

type Subscriber struct {
	Engine    Engine
	PubSubSub *pubsub.Subscriber
}

func (s *Subscriber) Run(ctx context.Context) error {
	return s.PubSubSub.Receive(ctx, func(ctx context.Context, m *pubsub.Message) {
		if taskType := m.Attributes["type"]; taskType != "update" {
			logger.InfoContext(ctx, "Skipping message, not an update", slog.Any("task_type", taskType))
			m.Ack()

			return
		}

		taskCtx := otel.GetTextMapPropagator().Extract(ctx, propagation.MapCarrier(m.Attributes))
		taskCtx, span := otel.Tracer("worker").Start(taskCtx, "process_message")
		defer span.End()
		task := Task{
			SourceID:     m.Attributes["source"],
			PathInSource: m.Attributes["path"],
		}
		logInfo := []any{
			slog.String("source", task.SourceID),
			slog.String("path", task.PathInSource),
		}
		if len(m.Data) != 0 {
			if m.Attributes["content_encoding"] != "zstd" {
				logger.ErrorContext(taskCtx, "Unrecognized content encoding", append(logInfo, slog.String("encoding", m.Attributes["content_encoding"]))...)
				m.Nack()

				return
			}
			buf := make([]byte, 0, len(m.Data)*3) // let's guess 3x compression
			buf, err := zstd.DecodeTo(buf, m.Data)
			if err != nil {
				logger.ErrorContext(taskCtx, "Failed to decompress vulnerability", append(logInfo, slog.Any("error", err))...)
				m.Nack()

				return
			}
			task.Vuln = &osvschema.Vulnerability{}
			if err := proto.Unmarshal(buf, task.Vuln); err != nil {
				logger.ErrorContext(taskCtx, "Failed to unmarshal vulnerability", append(logInfo, slog.Any("error", err))...)
				m.Nack()

				return
			}
		}
		deleted, err := strconv.ParseBool(m.Attributes["deleted"])
		if err != nil {
			logger.ErrorContext(taskCtx, "Failed to parse deleted attribute, defaulting to false", append(logInfo, slog.Any("error", err))...)
			deleted = false
		}
		task.IsDeleted = deleted

		timestamp, err := strconv.ParseInt(m.Attributes["req_timestamp"], 10, 64)
		if err != nil {
			logger.ErrorContext(taskCtx, "Failed to parse req_timestamp attribute, ignoring", append(logInfo, slog.Any("error", err))...)
		} else {
			ts := time.Unix(timestamp, 0)
			task.ReceivedTime = &ts
		}
		srcTime := m.Attributes["src_timestamp"]
		if srcTime != "" {
			timestamp, err = strconv.ParseInt(srcTime, 10, 64)
			if err != nil {
				logger.ErrorContext(taskCtx, "Failed to parse src_timestamp attribute, ignoring", append(logInfo, slog.Any("error", err))...)
			} else {
				ts := time.Unix(timestamp, 0)
				task.SourceTime = &ts
			}
		}

		skipHash, ok := m.Attributes["skip_hash_check"]
		if !ok || skipHash != "true" {
			task.SHA256 = m.Attributes["original_sha256"]
		}

		if err := s.Engine.RunTask(taskCtx, task); err != nil {
			logger.ErrorContext(taskCtx, "Failed to process task", append(logInfo, slog.Any("error", err))...)
			m.Nack()
		} else {
			m.Ack()
		}
	})
}
