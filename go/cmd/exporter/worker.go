package main

import (
	"archive/zip"
	"bytes"
	"cmp"
	"compress/flate"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"go.opentelemetry.io/otel"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	gitEcosystem        = "GIT"
	vanirVulnsFilename  = "osv_git.json"
	allZipFilename      = "all.zip"
	modifiedCSVFilename = "modified_id.csv"
	ecosystemsFilename  = "ecosystems.txt"
)

// vulnMeta holds the ID, modified time, CRC32, and pre-compression sizes for a vulnerability.
type vulnMeta struct {
	id         string
	modified   time.Time
	crc32      uint32
	uncompSize uint64
	compSize   uint64
}

// csvEntry holds the modified time and the relative entry path.
type csvEntry struct {
	modified time.Time
	path     string
}

// processedVuln holds the metadata, ecosystems, and Vanir flag for a processed vulnerability.
type processedVuln struct {
	meta       vulnMeta
	ecosystems []string
	hasVanir   bool
}

// ecosystemWorker processes vulnerabilities for a single ecosystem.
type ecosystemWorker struct {
	ecosystem  string
	scratchDir string
	inCh       chan vulnMeta
}

// newEcosystemWorker creates and starts a new ecosystemWorker.
func newEcosystemWorker(ctx context.Context, ecosystem string, scratchDir string, outCh chan<- writeMsg, wg *sync.WaitGroup) *ecosystemWorker {
	ch := make(chan vulnMeta, 100)
	worker := &ecosystemWorker{
		ecosystem:  ecosystem,
		scratchDir: scratchDir,
		inCh:       ch,
	}
	wg.Add(1)
	go worker.run(ctx, outCh, wg)

	return worker
}

// run is the main loop for the ecosystemWorker. It receives vulnerability metadata,
// aggregates them, and upon completion, writes out the ecosystem-specific
// zip and csv files.
func (w *ecosystemWorker) run(ctx context.Context, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	ctx, span := otel.Tracer("exporter").Start(ctx, w.ecosystem)
	defer span.End()

	logger.InfoContext(ctx, "new ecosystem worker started", slog.String("ecosystem", w.ecosystem))
	// 500 size is around the minimum each ecosystem would need, most ecosystems are much bigger.
	allVulns := make([]vulnMeta, 0, 500)
	csvData := make([]csvEntry, 0, 500)
	for v := range w.inCh {
		allVulns = append(allVulns, v)
		csvData = append(csvData, csvEntry{modified: v.modified, path: v.id})
	}

	if ctx.Err() != nil {
		return
	}

	logger.InfoContext(ctx, "All vulnerabilities processed", slog.String("ecosystem", w.ecosystem))
	writeModifiedIDCSV(ctx, filepath.Join(w.ecosystem, modifiedCSVFilename), csvData, outCh)
	writeZIP(ctx, filepath.Join(w.ecosystem, allZipFilename), allVulns, outCh, w.scratchDir)
	logger.InfoContext(ctx, "ecosystem worker finished processing", slog.String("ecosystem", w.ecosystem))
}

// Finish signals the worker to stop processing by closing its input channel.
func (w *ecosystemWorker) Finish() {
	close(w.inCh)
}

// vulnAndEcos holds a vulnerability metadata and the list of ecosystems it belongs to.
type vulnAndEcos struct {
	meta       vulnMeta
	ecosystems []string
}

// allEcosystemWorker processes all vulnerabilities from all ecosystems to create
// the global export files.
type allEcosystemWorker struct {
	scratchDir string
	inCh       chan vulnAndEcos
}

// newAllEcosystemWorker creates and starts a new allEcosystemWorker.
func newAllEcosystemWorker(ctx context.Context, scratchDir string, outCh chan<- writeMsg, wg *sync.WaitGroup) *allEcosystemWorker {
	ch := make(chan vulnAndEcos, 100)
	worker := &allEcosystemWorker{
		scratchDir: scratchDir,
		inCh:       ch,
	}
	wg.Add(1)
	go worker.run(ctx, outCh, wg)

	return worker
}

// run is the main loop for the allEcosystemWorker. It receives all vulnerabilities
// and generates the global all.zip, modified_id.csv, and ecosystems.txt files.
func (w *allEcosystemWorker) run(ctx context.Context, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	ctx, span := otel.Tracer("exporter").Start(ctx, "all-ecosystems")
	defer span.End()

	logger.InfoContext(ctx, "all-ecosystem worker started")
	// We have currently about 1.8 million entries, so start at 100k
	allVulns := make([]vulnMeta, 0, 100000)
	csvData := make([]csvEntry, 0, 100000)
	ecosystems := make(map[string]struct{})
	for v := range w.inCh {
		allVulns = append(allVulns, v.meta)
		for _, e := range v.ecosystems {
			ecosystems[e] = struct{}{}
			csvData = append(csvData, csvEntry{modified: v.meta.modified, path: e + "/" + v.meta.id})
			if len(csvData)%50000 == 0 {
				logger.InfoContext(ctx, "processed N vulnerabilities", slog.Int("n", len(csvData)))
			}
		}
	}

	if ctx.Err() != nil {
		return
	}

	writeModifiedIDCSV(ctx, modifiedCSVFilename, csvData, outCh)
	writeZIP(ctx, allZipFilename, allVulns, outCh, w.scratchDir)
	ecos := slices.Collect(maps.Keys(ecosystems))
	slices.Sort(ecos)
	ecoString := strings.Join(ecos, "\n") + "\n"
	write(ctx, ecosystemsFilename, []byte(ecoString), "text/plain", outCh)
	logger.InfoContext(ctx, "all-ecosystem worker finished processing")
}

// Finish signals the worker to stop processing by closing its input channel.
func (w *allEcosystemWorker) Finish() {
	close(w.inCh)
}

// marshalToJSON marshals the vulnerability proto to formatted JSON bytes.
func marshalToJSON(vuln *osvschema.Vulnerability) ([]byte, error) {
	b, err := protojson.Marshal(vuln)
	if err != nil {
		return nil, err
	}
	// Compact the JSON, removing extra spaces emitted by protojson.
	var out bytes.Buffer
	if err := json.Compact(&out, b); err != nil {
		return nil, err
	}

	return out.Bytes(), nil
}

// write is a helper to send a writeMsg to the writer channel, handling context cancellation.
func write(ctx context.Context, path string, data []byte, mimeType string, outCh chan<- writeMsg) {
	select {
	case outCh <- writeMsg{path: path, mimeType: mimeType, data: data}:
	case <-ctx.Done():
	}
}

// writeStream is a helper to send a streaming file writeMsg to the writer channel.
func writeStream(ctx context.Context, path string, filePath string, mimeType string, outCh chan<- writeMsg) {
	select {
	case outCh <- writeMsg{path: path, mimeType: mimeType, filePath: filePath}:
	case <-ctx.Done():
	}
}

// writeModifiedIDCSV constructs and writes a modified_id.csv file.
func writeModifiedIDCSV(ctx context.Context, path string, csvData []csvEntry, outCh chan<- writeMsg) {
	logger.InfoContext(ctx, "constructing csv file", slog.String("path", path))
	slices.SortFunc(csvData, func(a, b csvEntry) int {
		return cmp.Or(
			-a.modified.Compare(b.modified), // Modified date, descending
			cmp.Compare(a.path, b.path),     // path/vuln ID, ascending
		)
	})

	var buf bytes.Buffer
	wr := csv.NewWriter(&buf)
	for _, entry := range csvData {
		t := entry.modified.UTC().Format(time.RFC3339Nano)
		if err := wr.Write([]string{t, entry.path}); err != nil {
			logger.ErrorContext(ctx, "failed writing csv line", slog.String("path", path), slog.Any("err", err))
			return
		}
	}
	wr.Flush()
	if err := wr.Error(); err != nil {
		logger.ErrorContext(ctx, "failed flushing csv", slog.String("path", path), slog.Any("err", err))
		return
	}

	logger.InfoContext(ctx, "writing csv file", slog.String("path", path))
	write(ctx, path, buf.Bytes(), "text/csv", outCh)
}

// writeZIP constructs and writes a zip file by streaming pre-compressed local files via CreateRaw.
func writeZIP(ctx context.Context, path string, allVulns []vulnMeta, outCh chan<- writeMsg, scratchDir string) {
	logger.InfoContext(ctx, "constructing zip file", slog.String("path", path))
	slices.SortFunc(allVulns, func(a, b vulnMeta) int {
		return cmp.Compare(a.id, b.id)
	})

	tmpZip, err := os.CreateTemp(scratchDir, "zip-*.tmp")
	if err != nil {
		logger.ErrorContext(ctx, "failed to create temp zip file", slog.String("path", path), slog.Any("err", err))
		return
	}
	defer tmpZip.Close()

	wr := zip.NewWriter(tmpZip)
	for _, vuln := range allVulns {
		w, err := wr.CreateRaw(&zip.FileHeader{
			Name:               vuln.id + ".json",
			Modified:           vuln.modified,
			Method:             zip.Deflate,
			CRC32:              vuln.crc32,
			CompressedSize64:   vuln.compSize,
			UncompressedSize64: vuln.uncompSize,
		})
		if err != nil {
			logger.ErrorContext(ctx, "failed to create raw vuln in zip file", slog.String("id", vuln.id), slog.Any("err", err))
			continue
		}
		localPath := filepath.Join(scratchDir, vuln.id+".deflate")
		f, err := os.Open(localPath)
		if err != nil {
			logger.ErrorContext(ctx, "failed to open local vuln deflate file", slog.String("path", localPath), slog.Any("err", err))
			continue
		}
		if _, err := io.Copy(w, f); err != nil {
			logger.ErrorContext(ctx, "failed to write vuln deflate data to zip file", slog.String("id", vuln.id), slog.Any("err", err))
		}
		f.Close()
	}
	if err := wr.Close(); err != nil {
		logger.ErrorContext(ctx, "failed to close zip writer", slog.String("path", path), slog.Any("err", err))
		return
	}

	logger.InfoContext(ctx, "writing zip file", slog.String("path", path))
	writeStream(ctx, path, tmpZip.Name(), "application/zip", outCh)
}

// writeVanir constructs and writes the osv_git.json file containing vulnerabilities with Vanir signatures
// by reading the cached JSON files from disk and marshaling the combined JSON array in memory.
func writeVanir(ctx context.Context, vanirVulnIDs []string, outCh chan<- writeMsg, scratchDir string) {
	logger.InfoContext(ctx, "constructing vanir file", slog.Int("count", len(vanirVulnIDs)))
	slices.Sort(vanirVulnIDs)

	vulns := make([]json.RawMessage, 0, len(vanirVulnIDs))
	for _, id := range vanirVulnIDs {
		localPath := filepath.Join(scratchDir, id+".deflate")
		f, err := os.Open(localPath)
		if err != nil {
			logger.ErrorContext(ctx, "failed to open local vuln file for vanir", slog.String("id", id), slog.Any("err", err))
			continue
		}
		fr := flate.NewReader(f)
		data, err := io.ReadAll(fr)
		_ = fr.Close()
		_ = f.Close()
		if err != nil {
			logger.ErrorContext(ctx, "failed to decompress local vuln file for vanir", slog.String("id", id), slog.Any("err", err))
			continue
		}
		vulns = append(vulns, data)
	}

	finalJSON, err := json.Marshal(vulns)
	if err != nil {
		logger.ErrorContext(ctx, "failed to marshal vanir JSON file", slog.Any("err", err))
		return
	}

	logger.InfoContext(ctx, "writing vanir file", slog.String("path", filepath.Join(gitEcosystem, vanirVulnsFilename)))
	write(ctx, filepath.Join(gitEcosystem, vanirVulnsFilename), finalJSON, "application/json", outCh)
}
