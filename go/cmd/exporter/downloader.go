package main

import (
	"bytes"
	"compress/flate"
	"context"
	"hash/crc32"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/google/osv.dev/go/internal/osvutil"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

var flateWriterPool = sync.Pool{
	New: func() any {
		fw, _ := flate.NewWriter(io.Discard, flate.DefaultCompression)
		return fw
	},
}

// downloadThenProcessor is a worker that receives GCS object handles from inCh, downloads
// the raw protobuf data, unmarshals it into a Vulnerability, marshals it to compact
// JSON, saves pre-compressed Deflate data to scratch disk, queues individual JSON uploads,
// and sends the metadata to routerCh.
func downloadThenProcessor(ctx context.Context, cancel context.CancelFunc, client clients.CloudStorage, scratchDir string, inCh <-chan string, routerCh chan<- processedVuln, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	for path := range inCh {
		// Process object.
		data, err := client.ReadObject(ctx, path)
		if err != nil {
			if osvutil.IsContextError(err) {
				return
			}
			logger.ErrorContext(ctx, "failed to read vulnerability", slog.String("obj", path), slog.Any("err", err))

			continue
		}
		vuln := &osvschema.Vulnerability{}
		if err := proto.Unmarshal(data, vuln); err != nil {
			if osvutil.IsContextError(err) {
				return
			}
			logger.ErrorContext(ctx, "failed to unmarshal vulnerability", slog.String("obj", path), slog.Any("err", err))

			continue
		}

		// Marshal JSON ONCE for this vulnerability.
		b, err := marshalToJSON(vuln)
		if err != nil {
			logger.ErrorContext(ctx, "failed to marshal vulnerability to json", slog.String("id", vuln.GetId()), slog.Any("err", err))
			continue
		}

		// Pre-compress using Deflate for zero-copy CreateRaw ZIP generation.
		var compBuf bytes.Buffer
		fw := flateWriterPool.Get().(*flate.Writer)
		fw.Reset(&compBuf)
		if _, err := fw.Write(b); err != nil {
			flateWriterPool.Put(fw)
			logger.ErrorContext(ctx, "failed to compress vulnerability json", slog.String("id", vuln.GetId()), slog.Any("err", err))
			cancel()

			return
		}
		if err := fw.Close(); err != nil {
			flateWriterPool.Put(fw)
			logger.ErrorContext(ctx, "failed to close flate writer", slog.String("id", vuln.GetId()), slog.Any("err", err))
			cancel()

			return
		}
		flateWriterPool.Put(fw)

		compressedBytes := compBuf.Bytes()
		crc := crc32.ChecksumIEEE(b)

		// Cache pre-compressed Deflate payload to local scratch disk.
		localPath := filepath.Join(scratchDir, vuln.GetId()+".deflate")
		if err := os.WriteFile(localPath, compressedBytes, 0600); err != nil {
			logger.ErrorContext(ctx, "failed to write cached vulnerability to disk", slog.String("id", vuln.GetId()), slog.Any("err", err))
			// Cancel the exporter context if writing to the scratch disk fails (e.g. disk full)
			// to fail fast rather than producing incomplete archives later.
			cancel()

			return
		}

		hasVanir := false
		// Check for Vanir signatures
		for _, aff := range vuln.GetAffected() {
			spec := aff.GetDatabaseSpecific()
			if _, ok := spec.GetFields()["vanir_signatures"]; ok {
				hasVanir = true
				break
			}
		}

		ecosystems := make(map[string]struct{})
		for _, aff := range vuln.GetAffected() {
			eco := aff.GetPackage().GetEcosystem()
			eco, _, _ = strings.Cut(eco, ":")
			if eco != "" {
				ecosystems[eco] = struct{}{}
			}
			for _, ref := range aff.GetRanges() {
				if ref.GetType() == osvschema.Range_GIT {
					ecosystems["GIT"] = struct{}{}
					break
				}
			}
		}
		if len(ecosystems) == 0 {
			ecosystems["[EMPTY]"] = struct{}{}
		}
		ecoNames := make([]string, 0, len(ecosystems))
		for eco := range ecosystems {
			ecoNames = append(ecoNames, eco)
			select {
			case writeCh <- writeMsg{path: filepath.Join(eco, vuln.GetId()) + ".json", mimeType: "application/json", data: b}:
			case <-ctx.Done():
				return
			}
		}

		// Send processed metadata to router.
		select {
		case routerCh <- processedVuln{
			meta: vulnMeta{
				id:         vuln.GetId(),
				modified:   vuln.GetModified().AsTime(),
				crc32:      crc,
				uncompSize: uint64(len(b)),
				compSize:   uint64(len(compressedBytes)),
			},
			ecosystems: ecoNames,
			hasVanir:   hasVanir,
		}:
		case <-ctx.Done():
			return
		}
	}
}
