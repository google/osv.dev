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

package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/metrics"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/prometheus/client_golang/prometheus"
)

type sourcePrefixes struct {
	name       string
	idPrefixes []string
}

func matchSource(id string, sources []sourcePrefixes) string {
	for _, s := range sources {
		if slices.ContainsFunc(s.idPrefixes, func(prefix string) bool {
			return strings.HasPrefix(id, prefix)
		}) {
			return s.name
		}
	}

	return "unknown"
}

// Stores holds the storage interfaces required by the metrics collector.
type Stores struct {
	SourceRepo     models.SourceRepositoryStore
	JobData        models.JobDataStore
	ImportFindings models.ImportFindingsStore
	GCS            clients.CloudStorage
	GCSProvider    clients.CloudStorageProvider
}

// Collector periodically collects dataset, drift, reconciler, deleter, linter, and CVE conversion state metrics
// from Datastore and GCS and exposes them as Prometheus gauges.
type Collector struct {
	stores Stores
}

// NewCollector creates a new Collector with the given stores.
func NewCollector(stores Stores) *Collector {
	return &Collector{stores: stores}
}

// CollectMetrics performs a single collection pass of batch/state metrics from Datastore and GCS.
func (c *Collector) CollectMetrics(ctx context.Context) {
	sources, fallbackLastUpdated, cveConversionBucket := c.sourcePrefixesAndLastUpdated(ctx)
	c.collectJobDataMetrics(ctx, sources)
	c.collectLinterFindingsMetrics(ctx, sources)
	c.collectDatasetAndExportMetrics(ctx, sources, fallbackLastUpdated)
	c.collectCVEConversionMetrics(ctx, cveConversionBucket)
}

func (c *Collector) sourcePrefixesAndLastUpdated(ctx context.Context) ([]sourcePrefixes, map[string]time.Time, string) {
	var sources []sourcePrefixes
	lastUpdatedTimes := make(map[string]time.Time)
	var cveConversionBucket string
	if c.stores.SourceRepo == nil {
		return sources, lastUpdatedTimes, ""
	}

	for source, err := range c.stores.SourceRepo.All(ctx) {
		if err != nil {
			logger.WarnContext(ctx, "custommetrics: failed to iterate SourceRepository", slog.Any("error", err))
			break
		}
		sources = append(sources, sourcePrefixes{
			name:       source.Name,
			idPrefixes: source.IDPrefixes,
		})
		if source.Name == "cve-osv" && source.Bucket != nil && source.Bucket.Name != "" {
			cveConversionBucket = source.Bucket.Name
		}

		var lastUpdated time.Time
		if source.Bucket != nil && source.Bucket.LastUpdated != nil {
			lastUpdated = *source.Bucket.LastUpdated
		} else if source.REST != nil && source.REST.LastUpdated != nil {
			lastUpdated = *source.REST.LastUpdated
		}
		if !lastUpdated.IsZero() {
			lastUpdatedTimes[source.Name] = lastUpdated
		}
	}

	return sources, lastUpdatedTimes, cveConversionBucket
}

func (c *Collector) collectJobDataMetrics(ctx context.Context, sources []sourcePrefixes) {
	if c.stores.JobData == nil {
		return
	}

	// 1. RecordChecker Drift & Invalid Records
	invalidIDs, err := models.GetJobData[[]string](ctx, c.stores.JobData, models.JobDataRecordCheckerInvalidRecords)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "custommetrics: failed to read recordchecker invalid records", slog.Any("error", err))
	} else {
		metrics.RecordCheckerDrift.WithLabelValues("gcs_missing_or_stale").Set(float64(len(invalidIDs)))
		countsBySource := make(map[string]int)
		for _, id := range invalidIDs {
			source := matchSource(id, sources)
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
	recSummary, err := models.GetJobData[models.ReconcilerSummary](ctx, c.stores.JobData, models.JobDataReconcilerSummary)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "custommetrics: failed to read reconciler summary", slog.Any("error", err))
	} else {
		metrics.ReconcilerRecordsReconciledTotal.WithLabelValues("up_to_date").Set(float64(recSummary.UpToDateCount))
		metrics.ReconcilerRecordsReconciledTotal.WithLabelValues("missing").Set(float64(recSummary.MissingCount))
		metrics.ReconcilerRecordsReconciledTotal.WithLabelValues("outdated").Set(float64(recSummary.OutdatedCount))
	}

	// 3. Deleter Summary
	delSummary, err := models.GetJobData[models.DeleterSummary](ctx, c.stores.JobData, models.JobDataDeleterSummary)
	if err != nil && !errors.Is(err, models.ErrNotFound) {
		logger.WarnContext(ctx, "custommetrics: failed to read deleter summary", slog.Any("error", err))
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

func (c *Collector) collectLinterFindingsMetrics(ctx context.Context, sources []sourcePrefixes) {
	if c.stores.ImportFindings == nil {
		return
	}

	findings, err := c.stores.ImportFindings.ListAll(ctx)
	if err != nil {
		logger.WarnContext(ctx, "custommetrics: failed to list ImportFindings", slog.Any("error", err))
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
			source = matchSource(f.BugID, sources)
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

func (c *Collector) collectDatasetAndExportMetrics(ctx context.Context, sources []sourcePrefixes, fallbackLastUpdated map[string]time.Time) {
	latestBySource := make(map[string]time.Time)
	defer func() {
		for src, ts := range fallbackLastUpdated {
			if _, ok := latestBySource[src]; !ok {
				latestBySource[src] = ts
			}
		}
		if len(latestBySource) > 0 {
			metrics.ImporterLastNewRecordTimestampSeconds.Reset()
			for src, ts := range latestBySource {
				metrics.ImporterLastNewRecordTimestampSeconds.WithLabelValues(src).Set(float64(ts.Unix()))
			}
		}
	}()

	if c.stores.GCS == nil {
		return
	}

	// Root all.zip size
	if attrs, err := c.stores.GCS.ReadObjectAttrs(ctx, "all.zip"); err == nil {
		metrics.ExportZipSizeBytes.WithLabelValues("all").Set(float64(attrs.Size))
	} else if !errors.Is(err, clients.ErrNotFound) {
		logger.WarnContext(ctx, "custommetrics: failed to stat all.zip", slog.Any("error", err))
	}

	// Root modified_id.csv unique vulnerability count and per-source latest record timestamp
	if csvBytes, err := c.stores.GCS.ReadObject(ctx, "modified_id.csv"); err == nil {
		uniqueIDs := make(map[string]struct{})
		for line := range strings.SplitSeq(string(csvBytes), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			modStr, pathOrID, ok := strings.Cut(line, ",")
			if !ok {
				continue
			}
			vulnID := pathOrID
			if _, after, ok := strings.CutLast(pathOrID, "/"); ok {
				vulnID = after
			}
			if vulnID == "" {
				continue
			}
			if _, seen := uniqueIDs[vulnID]; seen {
				continue
			}
			uniqueIDs[vulnID] = struct{}{}
			if ts, err := time.Parse(time.RFC3339Nano, modStr); err == nil {
				if src := matchSource(vulnID, sources); src != "unknown" && ts.After(latestBySource[src]) {
					latestBySource[src] = ts
				}
			}
		}
		metrics.DatasetTotalVulnerabilities.WithLabelValues("all").Set(float64(len(uniqueIDs)))
	} else if !errors.Is(err, clients.ErrNotFound) {
		logger.WarnContext(ctx, "custommetrics: failed to read modified_id.csv", slog.Any("error", err))
	}

	// Per-ecosystem zip sizes and counts from ecosystems.txt
	ecoBytes, err := c.stores.GCS.ReadObject(ctx, "ecosystems.txt")
	if err != nil {
		if !errors.Is(err, clients.ErrNotFound) {
			logger.WarnContext(ctx, "custommetrics: failed to read ecosystems.txt", slog.Any("error", err))
		}

		return
	}

	for eco := range strings.SplitSeq(string(ecoBytes), "\n") {
		eco = strings.TrimSpace(eco)
		if eco == "" {
			continue
		}
		if attrs, err := c.stores.GCS.ReadObjectAttrs(ctx, eco+"/all.zip"); err == nil {
			metrics.ExportZipSizeBytes.WithLabelValues(eco).Set(float64(attrs.Size))
		}
		if ecoCSV, err := c.stores.GCS.ReadObject(ctx, eco+"/modified_id.csv"); err == nil {
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

type cnaScorecardSummary struct {
	CNA       string         `json:"cna"`
	TotalCVEs int            `json:"total_cves"`
	Outcomes  map[string]int `json:"outcomes"`
}

type conversionSummaryPayload struct {
	Converter        string                `json:"converter"`
	OutcomeCounts    map[string]int        `json:"outcome_counts"`
	VersionSources   map[string]int        `json:"version_sources"`
	ReferenceTypes   map[string]int        `json:"reference_types"`
	ResolvedRanges   int                   `json:"resolved_ranges"`
	UnresolvedRanges int                   `json:"unresolved_ranges"`
	CNAScorecards    []cnaScorecardSummary `json:"cna_scorecards"`
}

func (c *Collector) collectCVEConversionMetrics(ctx context.Context, discoveredBucket string) {
	if c.stores.GCSProvider == nil {
		return
	}

	bucketName := os.Getenv("OSV_CVE_CONVERSION_BUCKET")
	if bucketName == "" {
		bucketName = discoveredBucket
	}
	if bucketName == "" {
		bucketName = "osv-test-cve-osv-conversion"
	}

	bkt := c.stores.GCSProvider.Bucket(bucketName)
	if bkt == nil {
		return
	}

	converters := []struct {
		name           string
		outcomesPrefix string
	}{
		{name: "cve5", outcomesPrefix: "metadata/cve5/outcomes"},
		{name: "nvd", outcomesPrefix: "metadata/nvd/outcomes"},
	}

	for _, conv := range converters {
		summaryPath := conv.outcomesPrefix + "/conversion-summary.json"
		data, err := bkt.ReadObject(ctx, summaryPath)
		if err == nil {
			var summary conversionSummaryPayload
			if unmarshalErr := json.Unmarshal(data, &summary); unmarshalErr != nil {
				logger.WarnContext(ctx, "custommetrics: failed to unmarshal conversion-summary.json",
					slog.String("converter", conv.name), slog.Any("error", unmarshalErr))

				continue
			}

			convLabels := prometheus.Labels{"converter": conv.name}
			metrics.CVEConversionOutcomesTotal.DeletePartialMatch(convLabels)
			for outcome, cnt := range summary.OutcomeCounts {
				metrics.CVEConversionOutcomesTotal.WithLabelValues(conv.name, outcome).Set(float64(cnt))
			}
			metrics.CVERangeSourcesTotal.DeletePartialMatch(convLabels)
			for src, cnt := range summary.VersionSources {
				metrics.CVERangeSourcesTotal.WithLabelValues(conv.name, src).Set(float64(cnt))
			}
			metrics.CVEReferenceTypesTotal.DeletePartialMatch(convLabels)
			for refType, cnt := range summary.ReferenceTypes {
				metrics.CVEReferenceTypesTotal.WithLabelValues(conv.name, refType).Set(float64(cnt))
			}
			metrics.CVEResolvedRangesTotal.WithLabelValues(conv.name, "resolved").Set(float64(summary.ResolvedRanges))
			metrics.CVEResolvedRangesTotal.WithLabelValues(conv.name, "unresolved").Set(float64(summary.UnresolvedRanges))

			if conv.name == "cve5" && len(summary.CNAScorecards) > 0 {
				metrics.CVECNAOutcomesTotal.Reset()
				limit := min(len(summary.CNAScorecards), 50)
				for _, card := range summary.CNAScorecards[:limit] {
					for outcome, cnt := range card.Outcomes {
						metrics.CVECNAOutcomesTotal.WithLabelValues(card.CNA, outcome).Set(float64(cnt))
					}
				}
			}

			continue
		}

		if !errors.Is(err, clients.ErrNotFound) {
			logger.WarnContext(ctx, "custommetrics: failed to read conversion-summary.json",
				slog.String("converter", conv.name), slog.Any("error", err))

			continue
		}

		// Fallback to latest outcomes CSV if conversion-summary.json has not been generated yet.
		c.collectCVEOutcomesFromLatestCSV(ctx, bkt, conv.name, conv.outcomesPrefix)
	}
}

func (c *Collector) collectCVEOutcomesFromLatestCSV(ctx context.Context, bkt clients.CloudStorage, converter, outcomesPrefix string) {
	var latestCSV string
	for obj, err := range bkt.Objects(ctx, outcomesPrefix+"/") {
		if err != nil {
			logger.WarnContext(ctx, "custommetrics: failed to list outcomes directory",
				slog.String("converter", converter), slog.Any("error", err))

			return
		}
		if obj != nil && strings.HasSuffix(obj.Name, ".csv") && obj.Name > latestCSV {
			latestCSV = obj.Name
		}
	}
	if latestCSV == "" {
		return
	}

	csvBytes, err := bkt.ReadObject(ctx, latestCSV)
	if err != nil {
		if !errors.Is(err, clients.ErrNotFound) {
			logger.WarnContext(ctx, "custommetrics: failed to read outcomes CSV",
				slog.String("object", latestCSV), slog.Any("error", err))
		}

		return
	}

	reader := csv.NewReader(bytes.NewReader(csvBytes))
	records, err := reader.ReadAll()
	if err != nil || len(records) <= 1 {
		return
	}

	counts := make(map[string]int)
	for _, row := range records[1:] {
		if len(row) >= 2 && row[1] != "" {
			counts[row[1]]++
		}
	}
	metrics.CVEConversionOutcomesTotal.DeletePartialMatch(prometheus.Labels{"converter": converter})
	for outcome, cnt := range counts {
		metrics.CVEConversionOutcomesTotal.WithLabelValues(converter, outcome).Set(float64(cnt))
	}
}
