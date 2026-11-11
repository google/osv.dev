package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/osv.dev/go/internal/osvutil"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"golang.org/x/sync/errgroup"
)

// Filenames written by the exporter (see go/cmd/exporter/worker.go).
const (
	ecosystemsFilename  = "ecosystems.txt"
	modifiedCSVFilename = "modified_id.csv"
)

type deleterConfig struct {
	MinAge       time.Duration // Only delete objects last updated at least this long ago.
	ThresholdPct float64       // Abort if more than this percent of vulnerability files would be deleted.
	DryRun       bool
	NumWorkers   int
	Now          func() time.Time
}

// runDeleter deletes "<ECOSYSTEM>/<ID>.json" files that are not listed in that
// ecosystem's modified_id.csv, for every ecosystem in the root ecosystems.txt.
// All other folders (e.g. all/) are ignored.
func runDeleter(ctx context.Context, b clients.CloudStorage, cfg deleterConfig) error {
	cfg.NumWorkers = max(cfg.NumWorkers, 1) // SetLimit(0) would block forever.
	ecosystems, err := readEcosystems(ctx, b)
	if err != nil {
		return err
	}

	var mu sync.Mutex
	var candidates []*clients.Object
	total := 0
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(cfg.NumWorkers)
	for _, eco := range ecosystems {
		g.Go(func() error {
			stale, n, err := findStale(gctx, b, eco)
			mu.Lock()
			defer mu.Unlock()
			candidates = append(candidates, stale...)
			total += n

			return err
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	sample := make([]string, 0, min(len(candidates), 100))
	for _, obj := range candidates[:cap(sample)] {
		sample = append(sample, obj.Name)
	}
	logger.InfoContext(ctx, "found files not in latest export",
		slog.Int("count", len(candidates)), slog.Int("total", total), slog.Any("sample", sample))
	if len(candidates) == 0 {
		return nil
	}
	if pct := float64(len(candidates)) / float64(total) * 100; pct > cfg.ThresholdPct {
		return fmt.Errorf("cowardly refusing to delete %d of %d files (%.2f%% > %.2f%%)", len(candidates), total, pct, cfg.ThresholdPct)
	}
	if cfg.DryRun {
		return nil
	}

	return deleteOld(ctx, b, candidates, cfg)
}

// readEcosystems reads the list of exported ecosystem folders from ecosystems.txt.
func readEcosystems(ctx context.Context, b clients.CloudStorage) ([]string, error) {
	data, err := b.ReadObject(ctx, ecosystemsFilename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %w", ecosystemsFilename, err)
	}
	var ecosystems []string
	for line := range strings.Lines(string(data)) {
		if eco := strings.TrimSpace(line); eco != "" {
			ecosystems = append(ecosystems, eco)
		}
	}
	if len(ecosystems) == 0 {
		return nil, fmt.Errorf("%s is empty", ecosystemsFilename)
	}

	return ecosystems, nil
}

// findStale returns the vulnerability files in an ecosystem folder that are
// not in its modified_id.csv, and the total number of vulnerability files.
func findStale(ctx context.Context, b clients.CloudStorage, eco string) ([]*clients.Object, int, error) {
	prefix := eco + "/"
	data, err := b.ReadObject(ctx, prefix+modifiedCSVFilename)
	if errors.Is(err, clients.ErrNotFound) {
		logger.WarnContext(ctx, "skipping ecosystem without modified_id.csv", slog.String("ecosystem", eco))
		return nil, 0, nil
	}
	if err != nil {
		return nil, 0, fmt.Errorf("failed to read %s: %w", prefix+modifiedCSVFilename, err)
	}
	ids, err := parseModifiedCSV(data)
	if err != nil {
		return nil, 0, fmt.Errorf("failed to parse %s: %w", prefix+modifiedCSVFilename, err)
	}
	if len(ids) == 0 {
		// The exporter only writes a CSV for non-empty ecosystems, so this is suspicious.
		logger.WarnContext(ctx, "skipping ecosystem with empty modified_id.csv", slog.String("ecosystem", eco))
		return nil, 0, nil
	}

	start := time.Now()
	var stale []*clients.Object
	total := 0
	for obj, err := range b.Objects(ctx, prefix) {
		if err != nil {
			return nil, 0, fmt.Errorf("failed to list %s: %w", prefix, err)
		}
		// Only consider "<ID>.json" files directly in the folder. GIT/osv_git.json
		// is the only other .json file the exporter writes there.
		file := strings.TrimPrefix(obj.Name, prefix)
		id, ok := strings.CutSuffix(file, ".json")
		if !ok || strings.Contains(id, "/") || file == "osv_git.json" {
			continue
		}
		total++
		if _, ok := ids[id]; !ok {
			stale = append(stale, obj)
		}
	}
	logger.InfoContext(ctx, "scanned ecosystem", slog.String("ecosystem", eco),
		slog.Int("files", total), slog.Int("stale", len(stale)), slog.Duration("took", time.Since(start)))

	return stale, total, nil
}

// parseModifiedCSV returns the set of IDs in a "<modified>,<ID>" CSV.
func parseModifiedCSV(data []byte) (map[string]struct{}, error) {
	r := csv.NewReader(bytes.NewReader(data))
	r.FieldsPerRecord = 2
	records, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	ids := make(map[string]struct{}, len(records))
	for _, rec := range records {
		ids[rec[1]] = struct{}{}
	}

	return ids, nil
}

// deleteOld deletes the candidates that were last updated before now-MinAge.
// Newer files may have been written by an in-progress export. Deletes are
// conditional on the listed generation, so files rewritten since are kept.
func deleteOld(ctx context.Context, b clients.CloudStorage, candidates []*clients.Object, cfg deleterConfig) error {
	cutoff := cfg.Now().Add(-cfg.MinAge)
	var deleted, failed atomic.Int64
	var g errgroup.Group
	g.SetLimit(cfg.NumWorkers)
	for _, obj := range candidates {
		if ctx.Err() != nil {
			break
		}
		if !obj.Attrs.Updated.Before(cutoff) {
			continue
		}
		g.Go(func() error {
			err := b.DeleteObject(ctx, obj.Name, &clients.DeleteOptions{IfGenerationMatches: &obj.Attrs.Generation})
			switch {
			case err == nil:
				deleted.Add(1)
			case errors.Is(err, clients.ErrNotFound), errors.Is(err, clients.ErrPreconditionFailed), osvutil.IsContextError(err):
				// Already gone, rewritten since listing, or shutting down.
			default:
				failed.Add(1)
				logger.ErrorContext(ctx, "failed to delete", slog.String("object", obj.Name), slog.Any("err", err))
			}

			return nil
		})
	}
	_ = g.Wait()

	logger.InfoContext(ctx, "deletion complete", slog.Int64("deleted", deleted.Load()), slog.Int64("failed", failed.Load()))
	if err := ctx.Err(); err != nil {
		return err
	}
	if n := failed.Load(); n > 0 {
		return fmt.Errorf("failed to delete %d files", n)
	}

	return nil
}
