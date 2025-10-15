package main

import (
	"archive/zip"
	"bytes"
	"cmp"
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

func spawnEcosystemWorker(ecosystem string, writeCh chan<- writeMsg, wg *sync.WaitGroup) *ecosystemWorker {
	ch := make(chan *osvschema.Vulnerability)
	worker := &ecosystemWorker{
		ecosystem: ecosystem,
		ch:        ch,
	}
	go worker.run(writeCh, wg)

	return worker
}

type vulnData struct {
	id   string
	data []byte
}

func (w *ecosystemWorker) run(writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("new ecosystem worker started", slog.String("ecosystem", w.ecosystem))
	var allVulns []vulnData
	var csvData [][]string
	for v := range w.ch {
		b, err := protojson.Marshal(v)
		if err != nil {
			logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
			continue
		}
		writeCh <- writeMsg{path: filepath.Join(w.ecosystem, v.GetId()) + ".json", mimeType: "application/json", data: b}
		allVulns = append(allVulns, vulnData{id: v.GetId(), data: b})
		csvData = append(csvData, []string{v.GetModified().AsTime().Format(time.RFC3339Nano), v.GetId()})
	}
	logger.Info("All vulnerabilities processed", slog.String("ecosystem", w.ecosystem))

	writeCSV(filepath.Join(w.ecosystem, "modified_id.csv"), csvData, writeCh)
	writeZip(filepath.Join(w.ecosystem, "all.zip"), allVulns, writeCh)
	logger.Info("ecosystem worker finished processing", slog.String("ecosystem", w.ecosystem))
}

func (w *ecosystemWorker) Finish() {
	close(w.ch)
}


type vulnAndEcos struct {
	*osvschema.Vulnerability
	ecosystems []string
}

func allWorker(ch <-chan vulnAndEcos, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	var allVulns []vulnData
	var csvData [][]string
	for v := range ch {
		b, err := protojson.Marshal(v.Vulnerability)
		if err != nil {
			logger.Error("failed to marshal vulnerability to json", slog.String("id", v.GetId()), slog.Any("err", err))
			continue
		}
		allVulns = append(allVulns, vulnData{id: v.GetId(), data: b})
		for _, e := range v.ecosystems {
			csvData = append(csvData, []string{v.GetModified().AsTime().Format(time.RFC3339Nano), e + "/" + v.GetId()})
		}
	}
	writeCSV("modified_id.csv", csvData, writeCh)
	writeZip("all.zip", allVulns, writeCh)
}

func writeCSV(path string, csvData [][]string, writeCh chan<- writeMsg) {
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
	writeCh <- writeMsg{path: path, mimeType: "text/csv", data: buf.Bytes()}
}

func writeZip(path string, allVulns []vulnData, writeCh chan<- writeMsg) {
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
	wr.Close()
	writeCh <- writeMsg{path: path, mimeType: "application/zip", data: buf.Bytes()}
}
