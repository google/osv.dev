// Package worker contains the implementation for the vulnerability enrichment worker pipeline.
package worker

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"path"
	"strings"

	"cloud.google.com/go/pubsub/v2"
	"github.com/google/go-cmp/cmp"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/worker/pipeline"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/ecosystem"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type Engine struct {
	Stores   Stores
	Pipeline []pipeline.Enricher

	GitterHost        string
	GitterClient      *http.Client
	NotifyPyPI        bool
	EcosystemProvider *ecosystem.Provider
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
		PathInSource:      task.PathInSource,
		EcosystemProvider: e.EcosystemProvider,
		RelationsStore:    e.Stores.Relations,
	}
	var err error
	params.SourceRepo, err = e.Stores.SourceRepo.Get(ctx, task.SourceID)
	if err != nil {
		return err
	}
	if task.Vuln == nil {
		return errors.New("vuln not provided")
	}

	// Get the current state of the vuln to check against
	current, err := e.Stores.Vulnerability.Get(ctx, task.Vuln.GetId())
	if err == nil {
		params.ExistingVuln = current
	} else if !errors.Is(err, models.ErrNotFound) {
		logger.ErrorContext(ctx, "Failed to get current vuln state", slog.String("vuln_id", task.Vuln.GetId()), slog.Any("error", err))

		return fmt.Errorf("failed to get current vuln state: %w", err)
	}

	enriched := proto.Clone(task.Vuln).(*osvschema.Vulnerability)
	for _, enricher := range e.Pipeline {
		if err := enricher.Enrich(ctx, enriched, &params); err != nil {
			logger.ErrorContext(ctx, "Enricher failed with error",
				slog.String("id", enriched.GetId()),
				slog.String("enricher", fmt.Sprintf("%T", enricher)),
				slog.Any("error", err),
			)

			return err
		}
	}

	commits, err := e.populateAffectedCommitsAndTags(ctx, enriched, params.SourceRepo)
	if err != nil {
		logger.ErrorContext(ctx, "Populate affected commits failed", slog.String("id", enriched.GetId()), slog.Any("error", err))

		return err
	}

	if params.ExistingVuln == nil || e.isSemanticallyDifferent(current, enriched) {
		enriched.Modified = timestamppb.Now()
	} else if current.GetModified().AsTime().After(enriched.GetModified().AsTime()) {
		enriched.Modified = current.GetModified()
	}

	// Ensure Modified is at least as new as Withdrawn
	if enriched.GetWithdrawn() != nil && enriched.GetWithdrawn().AsTime().After(enriched.GetModified().AsTime()) {
		enriched.Modified = enriched.GetWithdrawn()
	}

	if err := e.Stores.Vulnerability.Write(ctx, models.WriteRequest{
		ID:              enriched.GetId(),
		Source:          task.SourceID,
		Path:            task.PathInSource,
		Raw:             task.Vuln,
		Enriched:        enriched,
		AffectedCommits: commits,
	}); err != nil {
		return err
	}

	if e.NotifyPyPI {
		e.notifyPyPI(ctx, enriched, current)
	}

	// Remove ImportFindings
	if e.Stores.ImportFindings != nil {
		if err := e.Stores.ImportFindings.Clear(ctx, enriched.GetId()); err != nil {
			// Don't really want to return an error here since we successfully wrote the vuln
			logger.ErrorContext(ctx, "Failed to clear import findings", slog.String("vuln_id", enriched.GetId()), slog.Any("error", err))
		}
	}

	return nil
}

func (e *Engine) isSemanticallyDifferent(vuln1, vuln2 *osvschema.Vulnerability) bool {
	return !cmp.Equal(vuln1, vuln2,
		protocmp.Transform(),
		protocmp.IgnoreFields(&osvschema.Vulnerability{}, "modified", "published"),
	)
}

func (e *Engine) handleDelete(ctx context.Context, task Task) error {
	id := idFromPath(task.PathInSource)

	// Fetch the 'Last Known Good' state from the DB
	existing, ref, err := e.Stores.Vulnerability.GetWithMetadata(ctx, id)
	if errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "Requested deletion for non-existent record",
			slog.String("id", id),
			slog.String("path", task.PathInSource),
			slog.String("source", task.SourceID))

		return nil // Nothing to do
	}
	if err != nil {
		return err
	}

	// Safety Check: Does the record in the DB still belong to this path?
	if ref.Path != task.PathInSource {
		logger.WarnContext(ctx, "Skipping deletion: record moved",
			slog.String("id", id),
			slog.String("current_path", ref.Path),
			slog.String("requested_path", task.PathInSource))

		return nil
	}

	// Already withdrawn?
	if existing.GetWithdrawn() != nil {
		logger.InfoContext(ctx, "Vulnerability already withdrawn, skipping deletion", slog.String("id", id))

		return nil
	}

	// Set the withdrawn + modified dates
	withdrawn := proto.Clone(existing).(*osvschema.Vulnerability)
	withdrawn.Withdrawn = timestamppb.Now()
	withdrawn.Modified = timestamppb.Now()

	// Save the new "Withdrawn" state
	if err := e.Stores.Vulnerability.Write(ctx, models.WriteRequest{
		ID:       id,
		Source:   task.SourceID,
		Path:     task.PathInSource,
		Enriched: withdrawn,
		// When deleting, we clear the commit index
		AffectedCommits: models.AffectedCommitsResult{Skip: false, Commits: nil},
	}); err != nil {
		return err
	}

	// Notify PyPI
	if e.NotifyPyPI {
		e.notifyPyPI(ctx, withdrawn, existing)
	}

	return nil
}

// notifyPyPI publishes a message to a Pub/Sub topic.
// Note that this does not directly notify PyPI; a Cloud Run function
// consumes from this topic to handle the actual notification.
func (e *Engine) notifyPyPI(ctx context.Context, vuln, old *osvschema.Vulnerability) {
	if e.Stores.PyPIPublisher == nil {
		return
	}

	newHasPyPI := false
	for _, affected := range vuln.GetAffected() {
		if affected.GetPackage().GetEcosystem() == "PyPI" {
			newHasPyPI = true
			break
		}
	}

	oldHasPyPI := false
	if old != nil {
		for _, affected := range old.GetAffected() {
			if affected.GetPackage().GetEcosystem() == "PyPI" {
				oldHasPyPI = true
				break
			}
		}
	}

	// If neither has PyPI, nothing to do.
	if !newHasPyPI && !oldHasPyPI {
		return
	}

	toNotify := vuln
	// If it was removed from PyPI, we need to notify with a withdrawn date to trigger a deletion in the bridge.
	if oldHasPyPI && !newHasPyPI {
		toNotify = proto.Clone(vuln).(*osvschema.Vulnerability)
		toNotify.Withdrawn = timestamppb.Now()
		// Copy over the PyPI affected ranges from the old vuln so the bridge knows which project to withdraw.
		for _, affected := range old.GetAffected() {
			if affected.GetPackage().GetEcosystem() == "PyPI" {
				toNotify.Affected = append(toNotify.Affected, proto.Clone(affected).(*osvschema.Affected))
			}
		}
	}

	data, err := protojson.Marshal(toNotify)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to marshal vuln for PyPI notification", slog.String("id", vuln.GetId()), slog.Any("error", err))
		return
	}

	res := e.Stores.PyPIPublisher.Publish(ctx, &pubsub.Message{
		Data: data,
	})

	_, err = res.Get(ctx)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to publish PyPI notification", slog.String("id", vuln.GetId()), slog.Any("error", err))
	} else {
		logger.InfoContext(ctx, "Published PyPI notification", slog.String("id", vuln.GetId()))
	}
}

func idFromPath(p string) string {
	return strings.TrimSuffix(path.Base(p), path.Ext(p))
}
