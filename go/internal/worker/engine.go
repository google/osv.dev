// Package worker contains the implementation for the vulnerability enrichment worker pipeline.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Engine struct {
	Stores   Stores
	Pipeline []pipeline.Enricher
}

func (e *Engine) RunTask(ctx context.Context, task Task) error {
	switch task.Type {
	case TaskDelete:
		return e.handleDelete(ctx, task)
	case TaskUpdate:
		return e.handleUpdate(ctx, task)
	default:
		return fmt.Errorf("unknown task type: %v", task.Type)
	}
}

func (e *Engine) handleUpdate(ctx context.Context, task Task) error {
	params := pipeline.EnrichParams{
		PathInSource: task.PathInSource,
	}
	var err error
	params.SourceRepo, err = e.Stores.SourceRepo.Get(ctx, task.SourceID)
	if err != nil {
		return err
	}
	if task.Vuln == nil {
		// TODO: Download Vuln from source
		return errors.New("vuln not provided")
	}

	enriched := proto.Clone(task.Vuln).(*osvschema.Vulnerability)
	for _, enricher := range e.Pipeline {
		if err := enricher.Enrich(ctx, enriched, &params); err != nil {
			logger.ErrorContext(ctx, "Enricher failed with error",
				slog.String("id", task.Vuln.GetId()),
				slog.String("enricher", fmt.Sprintf("%T", enricher)),
				slog.Any("error", err),
			)

			return err
		}
	}

	// TODO: affected commits

	// Get the current state of the vuln to check against
	current, err := e.Stores.Vulnerability.Get(ctx, enriched.GetId())
	isNotFound := errors.Is(err, models.ErrNotFound)

	if err != nil && !isNotFound {
		logger.ErrorContext(ctx, "Failed to get current vuln state", slog.String("vuln_id", enriched.GetId()), slog.Any("error", err))

		return fmt.Errorf("failed to get current vuln state: %w", err)
	}

	if isNotFound || e.isSemanticallyDifferent(current, enriched) {
		enriched.Modified = timestamppb.Now()
	} else if current.GetModified().AsTime().After(enriched.GetModified().AsTime()) {
		enriched.Modified = current.GetModified()
	}

	return e.Stores.Vulnerability.Write(ctx, models.WriteRequest{
		ID:       enriched.GetId(),
		Source:   task.SourceID,
		Path:     task.PathInSource,
		Raw:      task.Vuln,
		Enriched: enriched,
		AffectedCommits: models.AffectedCommitsResult{
			Skip: true,
		},
	})
}

func (e *Engine) isSemanticallyDifferent(v1, v2 *osvschema.Vulnerability) bool {
	return !cmp.Equal(v1, v2,
		protocmp.Transform(),
		protocmp.IgnoreFields(&osvschema.Vulnerability{}, "modified", "published"),
	)
}

func (e *Engine) handleDelete(_ context.Context, _ Task) error {
	// TODO
	return nil
}
