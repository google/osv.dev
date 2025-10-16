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

type ecosystemWorker struct {
	ecosystem string
	ch        chan *osvschema.Vulnerability
}

func newEcosystemWorker(ctx context.Context, ecosystem string, writeCh chan<- writeMsg, wg *sync.WaitGroup) *ecosystemWorker {
	ch := make(chan *osvschema.Vulnerability)
	worker := &ecosystemWorker{
		ecosystem: ecosystem,
		ch:        ch,
	}
	go worker.run(ctx, writeCh, wg)

	return worker
}

type vulnData struct {
	id   string
	data []byte
}

var protoMarshaller = protojson.MarshalOptions{
	UseProtoNames: true,
}

func (w *ecosystemWorker) run(ctx context.Context, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("new ecosystem worker started", slog.String("ecosystem", w.ecosystem))
	var allVulns []vulnData
	var csvData [][]string
	var vanirVulns []vulnData
	for {
		var v *osvschema.Vulnerability
		var ok bool

		// Wait to receive a vulnerability, or be cancelled.
		select {
		case v, ok = <-w.ch:
			if !ok {
				logger.Info("All vulnerabilities processed", slog.String("ecosystem", w.ecosystem))
				writeCSV(ctx, filepath.Join(w.ecosystem, modifiedCSVFilename), csvData, writeCh)
				writeZip(ctx, filepath.Join(w.ecosystem, allZipFilename), allVulns, writeCh)
				if w.ecosystem == gitEcosystem {
					writeVanir(ctx, vanirVulns, writeCh)
				}
				logger.Info("ecosystem worker finished processing", slog.String("ecosystem", w.ecosystem))

				return
			}
		case <-ctx.Done():
			logger.Warn("ecosystem worker cancelled", slog.String("ecosystem", w.ecosystem), slog.Any("err", ctx.Err()))
			return
		}

		// Process vulnerability.
		b, err := protoMarshaller.Marshal(v)
		if err != nil {
			logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
			continue
		}

		// Wait to send the result, or be cancelled.
		select {
		case writeCh <- writeMsg{path: filepath.Join(w.ecosystem, v.GetId()) + ".json", mimeType: "application/json", data: b}:
		case <-ctx.Done():
			logger.Warn("ecosystem worker cancelled", slog.String("ecosystem", w.ecosystem), slog.Any("err", ctx.Err()))
			return
		}

		allVulns = append(allVulns, vulnData{id: v.GetId(), data: b})
		csvData = append(csvData, []string{v.GetModified().AsTime().Format(time.RFC3339Nano), v.GetId()})

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
}

func (w *ecosystemWorker) Finish() {
	close(w.ch)
}

type vulnAndEcos struct {
	*osvschema.Vulnerability

	ecosystems []string
}

type allWorker struct {
	ch chan vulnAndEcos
}

func newAllWorker(ctx context.Context, writeCh chan<- writeMsg, wg *sync.WaitGroup) *allWorker {
	ch := make(chan vulnAndEcos)
	worker := &allWorker{
		ch: ch,
	}
	go worker.run(ctx, writeCh, wg)

	return worker
}

func (w *allWorker) run(ctx context.Context, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	var allVulns []vulnData
	var csvData [][]string
	ecosystems := make(map[string]struct{})
	for {
		select {
		case v, ok := <-w.ch:
			if !ok {
				writeCSV(ctx, modifiedCSVFilename, csvData, writeCh)
				writeZip(ctx, allZipFilename, allVulns, writeCh)
				ecos := slices.Collect(maps.Keys(ecosystems))
				slices.Sort(ecos)
				ecoString := strings.Join(ecos, "\n")
				write(ctx, ecosystemsFilename, []byte(ecoString), "text/plain", writeCh)

				return
			}
			b, err := protojson.MarshalOptions{}.Marshal(v.Vulnerability)
			if err != nil {
				logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
				continue
			}
			allVulns = append(allVulns, vulnData{id: v.GetId(), data: b})
			for _, e := range v.ecosystems {
				ecosystems[e] = struct{}{}
				csvData = append(csvData, []string{v.GetModified().AsTime().Format(time.RFC3339Nano), e + "/" + v.GetId()})
			}
		case <-ctx.Done():
			logger.Warn("all worker cancelled", slog.Any("err", ctx.Err()))
			return
		}
	}
}

func (w *allWorker) Finish() {
	close(w.ch)
}

func write(ctx context.Context, path string, data []byte, mimeType string, writeCh chan<- writeMsg) {
	select {
	case writeCh <- writeMsg{path: path, mimeType: mimeType, data: data}:
	case <-ctx.Done():
	}
}

func writeCSV(ctx context.Context, path string, csvData [][]string, writeCh chan<- writeMsg) {
	slices.SortFunc(csvData, func(a, b []string) int {
		return cmp.Or(
			-cmp.Compare(a[0], b[0]),
			cmp.Compare(a[1], b[1]),
		)
	})

	var buf bytes.Buffer
	wr := csv.NewWriter(&buf)
	if err := wr.WriteAll(csvData); err != nil {
		logger.Error("failed writing csv", slog.String("path", path), slog.Any("err", err))
		return
	}
	wr.Flush()
	write(ctx, path, buf.Bytes(), "text/csv", writeCh)
}

func writeZip(ctx context.Context, path string, allVulns []vulnData, writeCh chan<- writeMsg) {
	slices.SortFunc(allVulns, func(a, b vulnData) int {
		return cmp.Compare(a.id, b.id)
	})
	var buf bytes.Buffer
	wr := zip.NewWriter(&buf)
	for _, vuln := range allVulns {
		w, err := wr.Create(vuln.id + ".json")
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
	write(ctx, path, buf.Bytes(), "application/zip", writeCh)
}

func writeVanir(ctx context.Context, vanirVulns []vulnData, writeCh chan<- writeMsg) {
	slices.SortFunc(vanirVulns, func(a, b vulnData) int { return cmp.Compare(a.id, b.id) })
	vulns := make([]json.RawMessage, len(vanirVulns))
	for i, v := range vanirVulns {
		vulns[i] = v.data
	}
	finalJSON, err := json.MarshalIndent(vulns, "", "  ")
	if err != nil {
		logger.Error("failed to marshal vanir JSON file", slog.Any("err", err))
		return
	}
	write(ctx, filepath.Join(gitEcosystem, vanirVulnsFilename), finalJSON, "application/json", writeCh)
}
