package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/proto"
)


func main() {
	logger.InitGlobalLogger()

	outBucketName := flag.String("bucket", "osv-vulnerabilities", "Bucket name to export to")
	vulnBucketName := flag.String("osv_vulns_bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "Bucket to read vuln protos from")
	local := flag.Bool("local", true, "")
	numWorkers := flag.Int("num_workers", 200, "Number of workers to download/upload")

	flag.Parse()

	if *vulnBucketName == "" {
		logger.Fatal("OSV_VULNERABILITIES_BUCKET must be set")
	}

	cl, err := storage.NewClient(context.Background())
	if err != nil {
		logger.Fatal("failed to create storage client", slog.Any("err", err))
	}

	vulnBucket := cl.Bucket(*vulnBucketName)
	var outBucket *storage.BucketHandle
	var outPrefix string
	if *local {
		outPrefix = *outBucketName
	} else {
		outBucket = cl.Bucket(*outBucketName)
	}

	objCh := make(chan *storage.ObjectHandle)
	resultsCh := make(chan *osvschema.Vulnerability)
	writeCh := make(chan writeMsg)

	var downloaderWg sync.WaitGroup
	for range *numWorkers / 2 {
		downloaderWg.Add(1)
		go downloader(context.Background(), objCh, resultsCh, &downloaderWg)
	}

	var writerWg sync.WaitGroup
	for range *numWorkers / 2 {
		writerWg.Add(1)
		go writer(context.Background(), writeCh, outBucket, outPrefix, &writerWg)
	}
	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(context.Background(), resultsCh, writeCh, &routerWg)

	it := vulnBucket.Objects(context.Background(), &storage.Query{Prefix: "all/pb/"})
	prevPrefix := ""
	for {
		attrs, err := it.Next()
		if errors.Is(err, iterator.Done) {
			break
		}
		if err != nil {
			logger.Fatal("failed to list objects", slog.Any("err", err))
		}
		prefix := filepath.Base(attrs.Name)
		prefix, _, _ = strings.Cut(prefix, "-")
		if prefix != prevPrefix {
			logger.Info("reached new prefix", slog.String("file", attrs.Name))
			prevPrefix = prefix
		}
		objCh <- vulnBucket.Object(attrs.Name)
	}

	close(objCh)
	downloaderWg.Wait()
	close(resultsCh)
	routerWg.Wait()
	close(writeCh)
	writerWg.Wait()
}

func downloader(ctx context.Context, objectCh <-chan *storage.ObjectHandle, resultsCh chan<- *osvschema.Vulnerability, wg *sync.WaitGroup) {
	defer wg.Done()
	for obj := range objectCh {
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
		select {
		case resultsCh <- vuln:
		case <-ctx.Done():
			return
		}
	}
}

func ecosystemRouter(ctx context.Context, inCh <-chan *osvschema.Vulnerability, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	workers := make(map[string]*ecosystemWorker)
	var workersWg sync.WaitGroup
	allWorkerChan := make(chan vulnAndEcos)
	workersWg.Add(1)
	go allWorker(allWorkerChan, writeCh, &workersWg)
	for vuln := range inCh {
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
				}
			}
		}
		if len(ecosystems) == 0 {
			ecosystems["[EMPTY]"] = struct{}{}
		}
		eco_names := make([]string, 0, len(ecosystems))
		for eco := range ecosystems {
			eco_names = append(eco_names, eco)
			worker, ok := workers[eco]
			if !ok {
				workersWg.Add(1)
				worker = spawnEcosystemWorker(eco, writeCh, &workersWg)
				workers[eco] = worker
			}
			worker.ch <- vuln
		}
		allWorkerChan <- vulnAndEcos{Vulnerability: vuln, ecosystems: eco_names}
	}

	for _, worker := range workers {
		worker.Finish()
	}
	close(allWorkerChan)
	workersWg.Wait()
}
