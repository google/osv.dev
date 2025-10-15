package main

import (
	"archive/zip"
	"bytes"
	"cmp"
	"context"
	"encoding/csv"
	"io"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
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

func (w *ecosystemWorker) run(ctx context.Context, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("new ecosystem worker started", slog.String("ecosystem", w.ecosystem))
	var allVulns []vulnData
	var csvData [][]string
	for {
		var v *osvschema.Vulnerability
		var ok bool

		// First, wait to receive a vulnerability, or be cancelled.
		select {
		case v, ok = <-w.ch:
			if !ok {
				logger.Info("All vulnerabilities processed", slog.String("ecosystem", w.ecosystem))
				writeCSV(ctx, filepath.Join(w.ecosystem, "modified_id.csv"), csvData, writeCh)
				writeZip(ctx, filepath.Join(w.ecosystem, "all.zip"), allVulns, writeCh)
				logger.Info("ecosystem worker finished processing", slog.String("ecosystem", w.ecosystem))
				return
			}
		case <-ctx.Done():
			logger.Warn("ecosystem worker cancelled", slog.String("ecosystem", w.ecosystem), slog.Any("err", ctx.Err()))
			return
		}

		// Now that we have a vulnerability, process it.
		b, err := protojson.Marshal(v)
		if err != nil {
			logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
			continue
		}

		// Now, wait to send the result, or be cancelled.
		select {
		case writeCh <- writeMsg{path: filepath.Join(w.ecosystem, v.GetId()) + ".json", mimeType: "application/json", data: b}:
		case <-ctx.Done():
			logger.Warn("ecosystem worker cancelled", slog.String("ecosystem", w.ecosystem), slog.Any("err", ctx.Err()))
			return
		}

		allVulns = append(allVulns, vulnData{id: v.GetId(), data: b})
		csvData = append(csvData, []string{v.GetModified().AsTime().Format(time.RFC3339Nano), v.GetId()})
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
	for {
		select {
		case v, ok := <-w.ch:
			if !ok {
				writeCSV(ctx, "modified_id.csv", csvData, writeCh)
				writeZip(ctx, "all.zip", allVulns, writeCh)
				return
			}
			b, err := protojson.Marshal(v.Vulnerability)
			if err != nil {
				logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
				continue
			}
			allVulns = append(allVulns, vulnData{id: v.GetId(), data: b})
			for _, e := range v.ecosystems {
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
func writeCSV(ctx context.Context, path string, csvData [][]string, writeCh chan<- writeMsg) {
	slices.SortFunc(csvData, func(a, b []string) int {
		return cmp.Or(
			-cmp.Compare(a[0], b[0]),
			cmp.Compare(a[1], b[1]),
		)
	})

	var buf bytes.Buffer
	wr := csv.NewWriter(&buf)
	wr.WriteAll(csvData)
	wr.Flush()
	select {
	case writeCh <- writeMsg{path: path, mimeType: "text/csv", data: buf.Bytes()}:
	case <-ctx.Done():
	}
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
	select {
	case writeCh <- writeMsg{path: path, mimeType: "application/zip", data: buf.Bytes()}:
	case <-ctx.Done():
	}
}
