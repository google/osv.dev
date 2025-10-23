package main

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"log/slog"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	gitEcosystem        = "GIT"
	vanirVulnsFilename  = "osv_git.json"
	allZipFilename      = "all.zip"
	modifiedCSVFilename = "modified_id.csv"
	ecosystemsFilename  = "ecosystems.txt"
)

// ecosystemWorker processes vulnerabilities for a single ecosystem.
type ecosystemWorker struct {
	ecosystem string
	inCh      chan *osvschema.Vulnerability
}

// newEcosystemWorker creates and starts a new ecosystemWorker.
func newEcosystemWorker(ctx context.Context, ecosystem string, outCh chan<- writeMsg, wg *sync.WaitGroup) *ecosystemWorker {
	ch := make(chan *osvschema.Vulnerability)
	worker := &ecosystemWorker{
		ecosystem: ecosystem,
		inCh:      ch,
	}
	wg.Add(1)
	go worker.run(ctx, outCh, wg)

	return worker
}

// vulnData holds the ID and marshalled JSON data for a vulnerability.
type vulnData struct {
	id       string
	modified time.Time
	data     []byte
}

// run is the main loop for the ecosystemWorker. It receives vulnerabilities,
// aggregates them, and upon completion, writes out the ecosystem-specific
// zip, csv, and (for GIT) vanir files.
func (w *ecosystemWorker) run(ctx context.Context, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("new ecosystem worker started", slog.String("ecosystem", w.ecosystem))
	var allVulns []vulnData
	var csvData [][]string
	var vanirVulns []vulnData
WorkLoop:
	for {
		var v *osvschema.Vulnerability
		var ok bool

		// Wait to receive a vulnerability, or be cancelled.
		select {
		case <-ctx.Done():
			logger.Warn("ecosystem worker cancelled", slog.String("ecosystem", w.ecosystem), slog.Any("err", ctx.Err()))
			return
		case v, ok = <-w.inCh:
			if !ok {
				break WorkLoop
			}
		}
		// Process vulnerability.
		b, err := marshalToJSON(v)
		if err != nil {
			logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
			continue
		}

		// Wait to send the result, or be cancelled.
		select {
		case outCh <- writeMsg{path: filepath.Join(w.ecosystem, v.GetId()) + ".json", mimeType: "application/json", data: b}:
		case <-ctx.Done():
			logger.Warn("ecosystem worker cancelled", slog.String("ecosystem", w.ecosystem), slog.Any("err", ctx.Err()))
			return
		}

		modified := v.GetModified().AsTime()
		allVulns = append(allVulns, vulnData{id: v.GetId(), modified: modified, data: b})
		csvData = append(csvData, []string{modified.Format(time.RFC3339Nano), v.GetId()})

		// For GIT ecosystem, we want to make a file containing every vulnerability with vanir signatures
		if w.ecosystem == gitEcosystem {
			for _, aff := range v.GetAffected() {
				spec := aff.GetDatabaseSpecific()
				if _, ok := spec.GetFields()["vanir_signatures"]; ok {
					vanirVulns = append(vanirVulns, vulnData{id: v.GetId(), data: b})
					break
				}
			}
		}
	}

	logger.Info("All vulnerabilities processed", slog.String("ecosystem", w.ecosystem))
	writeModifiedIDCSV(ctx, filepath.Join(w.ecosystem, modifiedCSVFilename), csvData, outCh)
	writeZIP(ctx, filepath.Join(w.ecosystem, allZipFilename), allVulns, outCh)
	if w.ecosystem == gitEcosystem {
		writeVanir(ctx, vanirVulns, outCh)
	}
	logger.Info("ecosystem worker finished processing", slog.String("ecosystem", w.ecosystem))
}

// Finish signals the worker to stop processing by closing its input channel.
func (w *ecosystemWorker) Finish() {
	close(w.inCh)
}

// vulnAndEcos holds a vulnerability and the list of ecosystems it belongs to.
type vulnAndEcos struct {
	*osvschema.Vulnerability

	ecosystems []string
}

// allEcosystemWorker processes all vulnerabilities from all ecosystems to create
// the global export files.
type allEcosystemWorker struct {
	inCh chan vulnAndEcos
}

// newAllEcosystemWorker creates and starts a new allEcosystemWorker.
func newAllEcosystemWorker(ctx context.Context, outCh chan<- writeMsg, wg *sync.WaitGroup) *allEcosystemWorker {
	ch := make(chan vulnAndEcos)
	worker := &allEcosystemWorker{
		inCh: ch,
	}
	wg.Add(1)
	go worker.run(ctx, outCh, wg)

	return worker
}

// run is the main loop for the allEcosystemWorker. It receives all vulnerabilities
// and generates the global all.zip, modified_id.csv, and ecosystems.txt files.
func (w *allEcosystemWorker) run(ctx context.Context, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("all-ecosystem worker started")
	var allVulns []vulnData
	var csvData [][]string
	ecosystems := make(map[string]struct{})
WorkLoop:
	for {
		select {
		case <-ctx.Done():
			logger.Warn("all-ecosystem worker cancelled", slog.Any("err", ctx.Err()))
			return
		case v, ok := <-w.inCh:
			if !ok {
				break WorkLoop
			}
			b, err := marshalToJSON(v.Vulnerability)
			if err != nil {
				logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
				continue
			}
			modified := v.GetModified().AsTime()
			allVulns = append(allVulns, vulnData{id: v.GetId(), modified: modified, data: b})
			for _, e := range v.ecosystems {
				ecosystems[e] = struct{}{}
				csvData = append(csvData, []string{modified.Format(time.RFC3339Nano), e + "/" + v.GetId()})
			}
		}
	}
	writeModifiedIDCSV(ctx, modifiedCSVFilename, csvData, outCh)
	writeZIP(ctx, allZipFilename, allVulns, outCh)
	ecos := slices.Collect(maps.Keys(ecosystems))
	slices.Sort(ecos)
	ecoString := strings.Join(ecos, "\n") + "\n"
	write(ctx, ecosystemsFilename, []byte(ecoString), "text/plain", outCh)
	logger.Info("all-ecosystem worker finished processing")
}

// Finish signals the worker to stop processing by closing its input channel.
func (w *allEcosystemWorker) Finish() {
	close(w.inCh)
}

var protoMarshaller = protojson.MarshalOptions{
	UseProtoNames: true, // TODO(michaelkedar): https://github.com/ossf/osv-schema/pull/442
}

// marshalToJSON marshals the vulnerability proto to formatted JSON bytes.
func marshalToJSON(vuln *osvschema.Vulnerability) ([]byte, error) {
	b, err := protoMarshaller.Marshal(vuln)
	if err != nil {
		return nil, err
	}
	// Compact the JSON, making output (more) stable.
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

// writeModifiedIDCSV constructs and writes a modified_id.csv file.
func writeModifiedIDCSV(ctx context.Context, path string, csvData [][]string, outCh chan<- writeMsg) {
	logger.Info("constructing csv file", slog.String("path", path))
	slices.SortFunc(csvData, func(a, b []string) int {
		return cmp.Or(
			-cmp.Compare(a[0], b[0]), // Modified date, descending
			cmp.Compare(a[1], b[1]),  // path/vuln ID, ascending
		)
	})

	var buf bytes.Buffer
	wr := csv.NewWriter(&buf)
	if err := wr.WriteAll(csvData); err != nil {
		logger.Error("failed writing csv", slog.String("path", path), slog.Any("err", err))
		return
	}
	wr.Flush()
	logger.Info("writing csv file", slog.String("path", path))
	write(ctx, path, buf.Bytes(), "text/csv", outCh)
}

// writeZIP constructs and writes an all.zip file.
func writeZIP(ctx context.Context, path string, allVulns []vulnData, outCh chan<- writeMsg) {
	logger.Info("constructing zip file", slog.String("path", path))
	slices.SortFunc(allVulns, func(a, b vulnData) int {
		return cmp.Compare(a.id, b.id)
	})
	var buf bytes.Buffer
	wr := zip.NewWriter(&buf)
	for _, vuln := range allVulns {
		w, err := wr.CreateHeader(&zip.FileHeader{
			Name:     vuln.id + ".json",
			Modified: vuln.modified,
			Method:   zip.Deflate,
		})
		if err != nil {
			logger.Error("failed to create vuln json in zip file", slog.String("id", vuln.id), slog.Any("err", err))
			continue
		}
		r := bytes.NewReader(vuln.data)
		if _, err := io.Copy(w, r); err != nil {
			logger.Error("failed to write vuln json in zip file", slog.String("id", vuln.id), slog.Any("err", err))
		}
	}
	if err := wr.Close(); err != nil {
		logger.Error("failed to close zip writer", slog.String("path", path), slog.Any("err", err))
	}
	logger.Info("writing zip file", slog.String("path", path))
	write(ctx, path, buf.Bytes(), "application/zip", outCh)
}

// writeVanir constructs and writes the osv_git.json file containing vulnerabilities with Vanir signatures.
func writeVanir(ctx context.Context, vanirVulns []vulnData, outCh chan<- writeMsg) {
	slices.SortFunc(vanirVulns, func(a, b vulnData) int { return cmp.Compare(a.id, b.id) })
	vulns := make([]json.RawMessage, len(vanirVulns))
	for i, v := range vanirVulns {
		vulns[i] = v.data
	}
	finalJSON, err := json.Marshal(vulns)
	if err != nil {
		logger.Error("failed to marshal vanir JSON file", slog.Any("err", err))
		return
	}
	write(ctx, filepath.Join(gitEcosystem, vanirVulnsFilename), finalJSON, "application/json", outCh)
}
