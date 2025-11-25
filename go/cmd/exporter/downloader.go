package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

// downloader is a worker that receives GCS object handles from inCh, downloads
// the raw protobuf data, unmarshals it into a Vulnerability, and sends the
// result to outCh.
func downloader(ctx context.Context, client clients.CloudStorage, inCh <-chan string, outCh chan<- *osvschema.Vulnerability, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		var path string
		var ok bool

		// Wait to receive an object path, or be cancelled.
		select {
		case path, ok = <-inCh:
			if !ok {
				return // Channel closed.
			}
		case <-ctx.Done():
			return
		}

		// Process object.
		data, err := client.ReadObject(ctx, path)
		if err != nil {
			logger.Error("failed to read vulnerability", slog.String("obj", path), slog.Any("err", err))
			continue
		}
		vuln := &osvschema.Vulnerability{}
		if err := proto.Unmarshal(data, vuln); err != nil {
			logger.Error("failed to unmarshal vulnerability", slog.String("obj", path), slog.Any("err", err))
			continue
		}

		// Wait to send the result, or be cancelled.
		select {
		case outCh <- vuln:
		case <-ctx.Done():
			return
		}
	}
}
