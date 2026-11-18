package worker

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/osv.dev/go/internal/metrics"
	"github.com/google/osv.dev/go/logger"
	"github.com/klauspost/compress/zstd"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/propagation"
	"google.golang.org/protobuf/encoding/protojson"
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
	start := time.Now()
	defer func() {
		metrics.RecordWorkerLatency(time.Since(start))
	}()

	workPool := m.Attributes["work_pool"]
	if workPool == "" {
		workPool = "default"
	}

	if taskType := m.Attributes["type"]; taskType != "update" {
		logger.InfoContext(ctx, "Skipping message, not an update", slog.Any("task_type", taskType))
		metrics.RecordWorkerTask(metrics.TaskStatusSkipped, metrics.TaskActionUnknown, workPool)
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
	task.Vuln, task.RawJSON, err = s.parseVuln(m)
	if err != nil {
		logger.ErrorContext(taskCtx, "Failed to parse vulnerability", append(logInfo, slog.Any("error", err))...)
		metrics.RecordWorkerTask(metrics.TaskStatusError, metrics.TaskActionUnknown, workPool)
		metrics.RecordWorkerFailedTask(metrics.WorkerErrorParse, false)
		m.Nack()

		return
	}

	deleted, err := strconv.ParseBool(m.Attributes["deleted"])
	if err != nil {
		logger.ErrorContext(taskCtx, "Failed to parse deleted attribute, defaulting to false", append(logInfo, slog.Any("error", err))...)
		deleted = false
	}
	action := metrics.TaskActionUpdate
	if deleted {
		task.Type = TaskDelete
		action = metrics.TaskActionDelete
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

	task.SHA256 = m.Attributes["original_sha256"]
	task.GitCommitHash = m.Attributes["git_commit"]
	if genStr := m.Attributes["gcs_generation"]; genStr != "" {
		if gen, err := strconv.ParseInt(genStr, 10, 64); err == nil {
			task.GCSGeneration = &gen
		} else {
			logger.ErrorContext(taskCtx, "Failed to parse gcs_generation attribute, ignoring", append(logInfo, slog.Any("error", err))...)
		}
	}

	if err := s.Engine.RunTask(taskCtx, task); err != nil {
		metrics.RecordWorkerTask(metrics.TaskStatusError, action, workPool)
		logger.ErrorContext(taskCtx, "Failed to process task", append(logInfo, slog.Any("error", err))...)
		m.Nack()
	} else {
		metrics.RecordWorkerTask(metrics.TaskStatusSuccess, action, workPool)
		if deleted {
			metrics.RecordUpstreamWithdrawal(task.SourceID)
		} else if workPool != "reimport" {
			metrics.RecordSourceRecordDiscovered(task.SourceID)
		}
		logTaskLatency(taskCtx, task, workPool)
		m.Ack()
	}
}

func (s *Subscriber) parseVuln(m *pubsub.Message) (*osvschema.Vulnerability, []byte, error) {
	if len(m.Data) == 0 {
		return nil, nil, nil
	}
	var data []byte
	switch m.Attributes["content_encoding"] {
	case "":
		data = m.Data
	case "zstd":
		// TODO: try to extract the actual uncompressed size from the zstd frame.
		data = make([]byte, 0, len(m.Data)*3)
		var err error
		data, err = zstd.DecodeTo(data, m.Data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decompress vulnerability: %w", err)
		}
	default:
		return nil, nil, fmt.Errorf("unrecognized content encoding: %s", m.Attributes["content_encoding"])
	}

	v := &osvschema.Vulnerability{}
	trimmed := bytes.TrimSpace(data)
	if m.Attributes["format"] == "json" || (len(trimmed) > 0 && trimmed[0] == '{') {
		unmarshaler := protojson.UnmarshalOptions{DiscardUnknown: true}
		if err := unmarshaler.Unmarshal(data, v); err != nil {
			return nil, nil, fmt.Errorf("failed to unmarshal JSON vulnerability: %w", err)
		}

		return v, data, nil
	}

	if err := proto.Unmarshal(data, v); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal vulnerability: %w", err)
	}

	return v, nil, nil
}

func (s *Subscriber) timeFromUnixSeconds(tsString string) (*time.Time, error) {
	timestamp, err := strconv.ParseInt(tsString, 10, 64)
	if err != nil {
		return nil, err
	}
	ts := time.Unix(timestamp, 0)

	return &ts, nil
}

func logTaskLatency(ctx context.Context, task Task, workPool string) {
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
		if workPool != "reimport" {
			metrics.RecordPublishedToAvailableLag(task.SourceID, srcLatency)
		}
	}
	logger.InfoContext(ctx, fmt.Sprintf("Task update (source_id=%s) latency %d", task.SourceID, latencySeconds), logAttrs...)
}
