package main

import (
	"context"
	"io"
	"log/slog"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/proto"
)

func downloader(ctx context.Context, inCh <-chan *storage.ObjectHandle, outCh chan<- *osvschema.Vulnerability, wg *sync.WaitGroup) {
	defer wg.Done()
	for {
		var obj *storage.ObjectHandle
		var ok bool

		// Wait to receive an object, or be cancelled.
		select {
		case obj, ok = <-inCh:
			if !ok {
				return // Channel closed.
			}
		case <-ctx.Done():
			return
		}

		// Process object.
		r, err := obj.NewReader(ctx)
		if err != nil {
			logger.Error("failed to open vulnerability", slog.String("obj", obj.ObjectName()), slog.Any("err", err))
			continue
		}
		data, err := io.ReadAll(r)
		r.Close()
		if err != nil {
			logger.Error("failed to read vulnerability", slog.String("obj", obj.ObjectName()), slog.Any("err", err))
			continue
		}
		vuln := &osvschema.Vulnerability{}
		if err := proto.Unmarshal(data, vuln); err != nil {
			logger.Error("failed to unmarshal vulnerability", slog.String("obj", obj.ObjectName()), slog.Any("err", err))
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
