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

package vanir

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

// Config holds configuration parameters for the Vanir signatures job.
type Config struct {
	BatchSize  int
	MaxWorkers int
	DryRun     bool
	Hours      int
	NowFunc    func() time.Time
}

// Runner orchestrates querying modified vulnerabilities, invoking Vanir signature
// generation in batches, and persisting enriched signatures back to the store.
type Runner struct {
	VulnStore models.VulnerabilityStore
	JobStore  models.JobDataStore
	Generator SignatureGenerator
	Config    Config
}

func (r *Runner) now() time.Time {
	if r.Config.NowFunc != nil {
		return r.Config.NowFunc().UTC()
	}

	return time.Now().UTC()
}

// Run executes the Vanir signature generation job.
func (r *Runner) Run(ctx context.Context) error {
	batchSize := r.Config.BatchSize
	if batchSize <= 0 {
		batchSize = 100
	}
	maxWorkers := r.Config.MaxWorkers
	if maxWorkers <= 0 {
		maxWorkers = 10
	}

	currentRun := r.now()

	var lastRun *time.Time
	if r.Config.Hours > 0 {
		t := currentRun.Add(-time.Duration(r.Config.Hours) * time.Hour)
		lastRun = &t
		logger.InfoContext(ctx, "Running Vanir signature generation for recent hours",
			slog.Int("hours", r.Config.Hours),
			slog.Time("since", t))
	} else {
		lr, err := models.GetJobData[time.Time](ctx, r.JobStore, JobDataLastRun)
		if err != nil && !errors.Is(err, models.ErrNotFound) {
			return err
		}
		if err == nil && !lr.IsZero() {
			lastRun = &lr
			logger.InfoContext(ctx, "Running Vanir signature generation since last run",
				slog.Time("last_run", lr))
		} else {
			logger.InfoContext(ctx, "No last run found, querying all vulnerabilities")
		}
	}

	retryList, err := models.GetJobData[[]string](ctx, r.JobStore, JobDataRetryList)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		return err
	}

	batchCh := make(chan []*osvschema.Vulnerability, maxWorkers)
	type batchOutcome struct {
		processed int
		generated int
		failedIDs []string
	}
	outcomeCh := make(chan batchOutcome, maxWorkers)

	var wg sync.WaitGroup
	for range maxWorkers {
		wg.Go(func() {
			for batch := range batchCh {
				generated, failedIDs := r.processBatch(ctx, batch)
				outcomeCh <- batchOutcome{
					processed: len(batch),
					generated: generated,
					failedIDs: failedIDs,
				}
			}
		})
	}

	go func() {
		wg.Wait()
		close(outcomeCh)
	}()

	var fatalErr error
	go func() {
		defer close(batchCh)
		seenIDs := make(map[string]struct{})
		currentBatch := make([]*osvschema.Vulnerability, 0, batchSize)

		enqueue := func(v *osvschema.Vulnerability) {
			if v == nil {
				return
			}
			id := v.GetId()
			if _, seen := seenIDs[id]; seen {
				return
			}
			seenIDs[id] = struct{}{}

			ok, reason := ShouldProcess(v)
			if !ok {
				logger.DebugContext(ctx, "Skipping vulnerability",
					slog.String("id", id),
					slog.String("reason", reason))

				return
			}

			currentBatch = append(currentBatch, v)
			if len(currentBatch) >= batchSize {
				batchCh <- currentBatch
				currentBatch = make([]*osvschema.Vulnerability, 0, batchSize)
			}
		}

		logger.InfoContext(ctx, "Streaming vulnerabilities for processing")
		for v, err := range r.VulnStore.ListModifiedSince(ctx, lastRun) {
			if err != nil {
				logger.ErrorContext(ctx, "Error streaming modified vulnerabilities", slog.Any("error", err))
				fatalErr = err

				return
			}
			enqueue(v)
		}

		if len(retryList) > 0 {
			logger.InfoContext(ctx, "Processing IDs from retry list", slog.Int("count", len(retryList)))
			for _, id := range retryList {
				if _, seen := seenIDs[id]; seen {
					continue
				}
				v, err := r.VulnStore.GetFull(ctx, id)
				if err != nil {
					if errors.Is(err, models.ErrNotFound) {
						logger.WarnContext(ctx, "Retry vulnerability not found in store", slog.String("id", id))
					} else {
						logger.ErrorContext(ctx, "Failed to fetch retry vulnerability, keeping in retry list", slog.String("id", id), slog.Any("error", err))
						outcomeCh <- batchOutcome{failedIDs: []string{id}}
					}

					continue
				}
				enqueue(v)
			}
		}

		if len(currentBatch) > 0 {
			batchCh <- currentBatch
		}
	}()

	totalProcessed := 0
	totalGenerated := 0
	var allFailedIDs []string

	for outcome := range outcomeCh {
		totalProcessed += outcome.processed
		totalGenerated += outcome.generated
		allFailedIDs = append(allFailedIDs, outcome.failedIDs...)
	}

	if fatalErr != nil {
		return fatalErr
	}

	logger.InfoContext(ctx, "Finished Vanir signature generation",
		slog.Int("processed", totalProcessed),
		slog.Int("generated", totalGenerated))

	slices.Sort(allFailedIDs)
	uniqueFailedIDs := slices.Compact(allFailedIDs)

	if r.Config.DryRun {
		logger.InfoContext(ctx, "Dry run: would have updated last_run", slog.Time("last_run", currentRun))
		if len(uniqueFailedIDs) > 0 {
			logger.InfoContext(ctx, "Dry run: would have saved failed IDs to retry list", slog.Int("count", len(uniqueFailedIDs)))
		}

		return nil
	}

	if err := r.JobStore.Set(ctx, JobDataLastRun, currentRun); err != nil {
		logger.ErrorContext(ctx, "Failed to update last run timestamp", slog.Any("error", err))
	}

	if err := r.JobStore.Set(ctx, JobDataRetryList, uniqueFailedIDs); err != nil {
		logger.ErrorContext(ctx, "Failed to update retry list", slog.Any("error", err))
	} else if len(uniqueFailedIDs) > 0 {
		logger.InfoContext(ctx, "Saved failed IDs to retry list", slog.Int("count", len(uniqueFailedIDs)))
	}

	return nil
}

func (r *Runner) processBatch(ctx context.Context, batch []*osvschema.Vulnerability) (int, []string) {
	if len(batch) == 0 {
		return 0, nil
	}

	logger.InfoContext(ctx, "Processing batch of vulnerabilities", slog.Int("count", len(batch)))

	batchTempDir, err := os.MkdirTemp("", "vanir-batch-*")
	if err != nil {
		logger.ErrorContext(ctx, "Failed to create temporary directory for batch", slog.Any("error", err))
		ids := make([]string, 0, len(batch))
		for _, v := range batch {
			ids = append(ids, v.GetId())
		}

		return 0, ids
	}
	defer os.RemoveAll(batchTempDir)

	sigMap, err := r.Generator.GenerateBatch(ctx, batch, batchTempDir)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to generate Vanir signatures for batch", slog.Int("count", len(batch)), slog.Any("error", err))
		ids := make([]string, 0, len(batch))
		for _, v := range batch {
			ids = append(ids, v.GetId())
		}

		return 0, ids
	}

	updatedCount := 0
	var failedIDs []string

	for _, origVuln := range batch {
		id := origVuln.GetId()
		sigsForVuln := sigMap[id]
		if len(sigsForVuln) == 0 {
			continue
		}

		if r.Config.DryRun {
			logger.InfoContext(ctx, "Dry run: would have updated vulnerability", slog.String("id", id))
			updatedCount++

			continue
		}

		updated, err := r.VulnStore.Mutate(ctx, id, ApplySignatures(sigsForVuln, r.now()))
		if err != nil {
			logger.ErrorContext(ctx, "Failed to update vulnerability with Vanir signatures, adding to retry list",
				slog.String("id", id),
				slog.Any("error", err))
			failedIDs = append(failedIDs, id)

			continue
		}
		if updated {
			updatedCount++
		}
	}

	return updatedCount, failedIDs
}
