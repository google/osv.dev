package main

import (
	"context"
	"errors"
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
	for path := range inCh {
		// Process object.
		data, err := client.ReadObject(ctx, path)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			logger.ErrorContext(ctx, "failed to read vulnerability", slog.String("obj", path), slog.Any("err", err))
			continue
		}
		vuln := &osvschema.Vulnerability{}
		if err := proto.Unmarshal(data, vuln); err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return
			}
			logger.ErrorContext(ctx, "failed to unmarshal vulnerability", slog.String("obj", path), slog.Any("err", err))
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
