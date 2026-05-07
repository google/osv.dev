package worker

import (
	"context"
	"fmt"
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
	return s.PubSubSub.Receive(ctx, s.handleMessage)
}

func (s *Subscriber) handleMessage(ctx context.Context, m *pubsub.Message) {
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

	var err error
	task.Vuln, err = s.parseVuln(m)
	if err != nil {
		logger.ErrorContext(taskCtx, "Failed to parse vulnerability", append(logInfo, slog.Any("error", err))...)
		m.Nack()

		return
	}

	deleted, err := strconv.ParseBool(m.Attributes["deleted"])
	if err != nil {
		logger.ErrorContext(taskCtx, "Failed to parse deleted attribute, defaulting to false", append(logInfo, slog.Any("error", err))...)
		deleted = false
	}
	if deleted {
		task.Type = TaskDelete
	} else {
		task.Type = TaskUpdate
	}

	task.ReceivedTime, err = s.timeFromUnixSeconds(m.Attributes["req_timestamp"])
	if err != nil {
		logger.ErrorContext(taskCtx, "Failed to parse req_timestamp attribute, ignoring", append(logInfo, slog.Any("error", err))...)
	}
	srcTime := m.Attributes["src_timestamp"]
	if srcTime != "" {
		task.SourceTime, err = s.timeFromUnixSeconds(srcTime)
		if err != nil {
			logger.ErrorContext(taskCtx, "Failed to parse src_timestamp attribute, ignoring", append(logInfo, slog.Any("error", err))...)
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
		logTaskLatency(taskCtx, task)
		m.Ack()
	}
}

func (s *Subscriber) parseVuln(m *pubsub.Message) (*osvschema.Vulnerability, error) {
	if len(m.Data) == 0 {
		//nolint:nilnil // this is expected for delete requests
		return nil, nil
	}
	if m.Attributes["content_encoding"] != "zstd" {
		return nil, fmt.Errorf("unrecognized content encoding: %s", m.Attributes["content_encoding"])
	}
	// TODO: try to extract the actual uncompressed size from the zstd frame.
	buf := make([]byte, 0, len(m.Data)*3)
	buf, err := zstd.DecodeTo(buf, m.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress vulnerability: %w", err)
	}
	v := &osvschema.Vulnerability{}
	if err := proto.Unmarshal(buf, v); err != nil {
		return nil, fmt.Errorf("failed to unmarshal vulnerability: %w", err)
	}

	return v, nil
}

func (s *Subscriber) timeFromUnixSeconds(tsString string) (*time.Time, error) {
	timestamp, err := strconv.ParseInt(tsString, 10, 64)
	if err != nil {
		return nil, err
	}
	ts := time.Unix(timestamp, 0)

	return &ts, nil
}

func logTaskLatency(ctx context.Context, task Task) {
	if task.ReceivedTime == nil {
		return
	}
	now := time.Now()
	latency := now.Sub(*task.ReceivedTime)
	latencySeconds := int64(latency.Seconds())
	logAttrs := []any{
		slog.Int64("latency", latencySeconds),
		slog.String("source", task.SourceID),
		slog.String("path", task.PathInSource),
	}
	if task.SourceTime != nil {
		srcLatency := now.Sub(*task.SourceTime)
		logAttrs = append(logAttrs, slog.Int64("src_latency", int64(srcLatency.Seconds())))
	}
	logger.InfoContext(ctx, fmt.Sprintf("Task update (source_id=%s) latency %d", task.SourceID, latencySeconds), logAttrs...)
}
