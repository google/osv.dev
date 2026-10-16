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

package recoverer

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/metrics"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
)

// StartMetricsCollector starts a background loop that periodically collects
// dataset, drift, reconciler, deleter, and linter state metrics from Datastore and GCS.
func (r *Recoverer) StartMetricsCollector(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 5 * time.Minute
	}
	go func() {
		r.CollectMetrics(ctx)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				r.CollectMetrics(ctx)
			}
		}
	}()
}

// CollectMetrics performs a single collection pass of batch/state metrics from Datastore and GCS.
func (r *Recoverer) CollectMetrics(ctx context.Context) {
	prefixToSource := r.collectSourceFreshnessAndPrefixes(ctx)
	r.collectJobDataMetrics(ctx, prefixToSource)
	r.collectLinterFindingsMetrics(ctx, prefixToSource)
	r.collectDatasetAndExportMetrics(ctx)
}

func (r *Recoverer) collectSourceFreshnessAndPrefixes(ctx context.Context) map[string]string {
	prefixToSource := make(map[string]string)
	if r.stores.SourceRepo == nil {
		return prefixToSource
	}

	for source, err := range r.stores.SourceRepo.All(ctx) {
		if err != nil {
			logger.WarnContext(ctx, "metrics_collector: failed to iterate SourceRepository", slog.Any("error", err))
			break
		}
		for _, p := range source.IDPrefixes {
			prefixToSource[p] = source.Name
		}

		var lastUpdated time.Time
		if source.Bucket != nil && source.Bucket.LastUpdated != nil {
			lastUpdated = *source.Bucket.LastUpdated
		} else if source.REST != nil && source.REST.LastUpdated != nil {
			lastUpdated = *source.REST.LastUpdated
		}
		if !lastUpdated.IsZero() {
			metrics.ImporterLastNewRecordTimestampSeconds.WithLabelValues(source.Name).Set(float64(lastUpdated.Unix()))
		}
	}

	return prefixToSource
}

func (r *Recoverer) collectJobDataMetrics(ctx context.Context, prefixToSource map[string]string) {
	if r.stores.JobData == nil {
		return
	}

	// 1. RecordChecker Drift & Invalid Records
	invalidIDs, err := models.GetJobData[[]string](ctx, r.stores.JobData, models.JobDataRecordCheckerInvalidRecords)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "metrics_collector: failed to read recordchecker invalid records", slog.Any("error", err))
	} else {
		metrics.RecordCheckerDrift.WithLabelValues("gcs_missing_or_stale").Set(float64(len(invalidIDs)))
		countsBySource := make(map[string]int)
		for _, id := range invalidIDs {
			prefix := strings.Split(id, "-")[0] + "-"
			source := prefixToSource[prefix]
			if source == "" {
				source = "unknown"
			}
			countsBySource[source]++
		}
		metrics.RecordCheckerInvalidRecords.Reset()
		if len(countsBySource) == 0 {
			metrics.RecordCheckerInvalidRecords.WithLabelValues("none").Set(0)
		} else {
			for src, cnt := range countsBySource {
				metrics.RecordCheckerInvalidRecords.WithLabelValues(src).Set(float64(cnt))
			}
		}
	}

	// 2. Reconciler Summary
	recSummary, err := models.GetJobData[models.ReconcilerSummary](ctx, r.stores.JobData, models.JobDataReconcilerSummary)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "metrics_collector: failed to read reconciler summary", slog.Any("error", err))
	} else {
		metrics.ReconcilerRecordsReconciledTotal.WithLabelValues("up_to_date").Set(float64(recSummary.UpToDateCount))
		metrics.ReconcilerRecordsReconciledTotal.WithLabelValues("missing").Set(float64(recSummary.MissingCount))
		metrics.ReconcilerRecordsReconciledTotal.WithLabelValues("outdated").Set(float64(recSummary.OutdatedCount))
	}

	// 3. Deleter Summary
	delSummary, err := models.GetJobData[models.DeleterSummary](ctx, r.stores.JobData, models.JobDataDeleterSummary)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "metrics_collector: failed to read deleter summary", slog.Any("error", err))
	} else {
		metrics.DeleterRefusedDeletionsTotal.Reset()
		if len(delSummary.RefusedBySource) == 0 {
			metrics.DeleterRefusedDeletionsTotal.WithLabelValues("none").Set(0)
		} else {
			for src, cnt := range delSummary.RefusedBySource {
				metrics.DeleterRefusedDeletionsTotal.WithLabelValues(src).Set(float64(cnt))
			}
		}
	}
}

func (r *Recoverer) collectLinterFindingsMetrics(ctx context.Context, prefixToSource map[string]string) {
	if r.stores.ImportFindings == nil {
		return
	}

	findings, err := r.stores.ImportFindings.ListAll(ctx)
	if err != nil {
		logger.WarnContext(ctx, "metrics_collector: failed to list ImportFindings", slog.Any("error", err))
		return
	}

	type findingKey struct {
		source   string
		ruleCode string
		severity string
	}
	counts := make(map[findingKey]int)
	for _, f := range findings {
		if f == nil {
			continue
		}
		source := f.Source
		if source == "" {
			prefix := strings.Split(f.BugID, "-")[0] + "-"
			source = prefixToSource[prefix]
			if source == "" {
				source = "unknown"
			}
		}
		for _, code := range f.Findings {
			if code == models.ImportFindingsNone {
				continue
			}
			ruleCode, severity := mapImportFindingToRuleAndSeverity(code)
			counts[findingKey{source: source, ruleCode: ruleCode, severity: severity}]++
		}
	}

	metrics.DataQualityFindingsTotal.Reset()
	for k, cnt := range counts {
		metrics.DataQualityFindingsTotal.WithLabelValues(k.source, k.ruleCode, k.severity).Set(float64(cnt))
	}
}

func mapImportFindingToRuleAndSeverity(code models.ImportFindings) (string, string) {
	switch code {
	case models.ImportFindingsInvalidJSON:
		return "SCH:001", "error"
	case models.ImportFindingsInvalidRecord:
		return "REC:001", "error"
	case models.ImportFindingsInvalidAliases:
		return "REC:002", "warning"
	case models.ImportFindingsInvalidUpstream:
		return "REC:003", "warning"
	case models.ImportFindingsInvalidRelated:
		return "REC:004", "warning"
	case models.ImportFindingsInvalidRange:
		return "RNG:001", "error"
	case models.ImportFindingsInvalidPackage:
		return "PKG:001", "error"
	case models.ImportFindingsInvalidVersion:
		return "PKG:002", "warning"
	case models.ImportFindingsInvalidPURL:
		return "PKG:003", "warning"
	case models.ImportFindingsInvalidCommit:
		return "COMMIT:001", "error"
	case models.ImportFindingsBadAliasedCVE:
		return "CVE:001", "warning"
	case models.ImportFindingsDeleted:
		return "DEL:001", "info"
	default:
		return "OTHER", "warning"
	}
}

func (r *Recoverer) collectDatasetAndExportMetrics(ctx context.Context) {
	if r.stores.GCS == nil {
		return
	}

	// Root all.zip size
	if attrs, err := r.stores.GCS.ReadObjectAttrs(ctx, "all.zip"); err == nil {
		metrics.ExportZipSizeBytes.WithLabelValues("all").Set(float64(attrs.Size))
	} else if !errors.Is(err, clients.ErrNotFound) {
		logger.WarnContext(ctx, "metrics_collector: failed to stat all.zip", slog.Any("error", err))
	}

	// Root modified_id.csv unique vulnerability count
	if csvBytes, err := r.stores.GCS.ReadObject(ctx, "modified_id.csv"); err == nil {
		uniqueIDs := make(map[string]struct{})
		for line := range strings.SplitSeq(string(csvBytes), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			_, pathOrID, ok := strings.Cut(line, ",")
			if !ok {
				continue
			}
			vulnID := pathOrID
			if _, after, ok := strings.CutLast(pathOrID, "/"); ok {
				vulnID = after
			}
			if vulnID != "" {
				uniqueIDs[vulnID] = struct{}{}
			}
		}
		metrics.DatasetTotalVulnerabilities.WithLabelValues("all").Set(float64(len(uniqueIDs)))
	} else if !errors.Is(err, clients.ErrNotFound) {
		logger.WarnContext(ctx, "metrics_collector: failed to read modified_id.csv", slog.Any("error", err))
	}

	// Per-ecosystem zip sizes and counts from ecosystems.txt
	ecoBytes, err := r.stores.GCS.ReadObject(ctx, "ecosystems.txt")
	if err != nil {
		if !errors.Is(err, clients.ErrNotFound) {
			logger.WarnContext(ctx, "metrics_collector: failed to read ecosystems.txt", slog.Any("error", err))
		}

		return
	}

	for eco := range strings.SplitSeq(string(ecoBytes), "\n") {
		eco = strings.TrimSpace(eco)
		if eco == "" {
			continue
		}
		if attrs, err := r.stores.GCS.ReadObjectAttrs(ctx, eco+"/all.zip"); err == nil {
			metrics.ExportZipSizeBytes.WithLabelValues(eco).Set(float64(attrs.Size))
		}
		if ecoCSV, err := r.stores.GCS.ReadObject(ctx, eco+"/modified_id.csv"); err == nil {
			count := 0
			for line := range strings.SplitSeq(string(ecoCSV), "\n") {
				if strings.TrimSpace(line) != "" {
					count++
				}
			}
			metrics.DatasetTotalVulnerabilities.WithLabelValues(eco).Set(float64(count))
		}
	}
}
