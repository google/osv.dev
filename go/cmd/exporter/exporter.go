// Package main runs the GCS exporter.
// The exporter is responsible for creating many files in the OSV vulnerabilities bucket:
// - [ECOSYSTEM]/VULN-ID.json - OSV JSON file for each vulnerability in each ecosystem
// - [ECOSYSTEM]/all.zip - contains each OSV JSON file for that ecosystem
// - [ECOSYSTEM]/modified_id.csv - contains the (modified, ID) of each vulnerability in the ecosystem directory
// - /ecosystems.txt - a line-separated list of each exported ecosystem
// - /all.zip - contains every OSV JSON file across all ecosytems
// - /modified_id.csv - the (modified, [ECOSYSTEM]/ID) of every vulnerability across all ecosystem directories
// - GIT/osv_git.json - a json array of every OSV vulnerability that has Vanir signatures.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/api/iterator"
)

func main() {
	logger.InitGlobalLogger()

	outBucketName := flag.String("bucket", "osv-vulnerabilities", "Output bucket or directory name. If -local is true, this is a local path; otherwise, it's a GCS bucket name.")
	vulnBucketName := flag.String("osv_vulns_bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "GCS bucket to read vulnerability protobufs from. Can also be set with the OSV_VULNERABILITIES_BUCKET environment variable.")
	local := flag.Bool("local", true, "If true, writes the output to a local directory specified by -bucket instead of a GCS bucket.")
	numWorkers := flag.Int("num_workers", 200, "The total number of concurrent workers to use for downloading from GCS and writing the output.")

	flag.Parse()

	if *vulnBucketName == "" {
		logger.Fatal("OSV_VULNERABILITIES_BUCKET must be set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cl, err := storage.NewClient(ctx)
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
		go downloader(ctx, objCh, resultsCh, &downloaderWg)
	}

	var writerWg sync.WaitGroup
	for range *numWorkers / 2 {
		writerWg.Add(1)
		go writer(ctx, cancel, writeCh, outBucket, outPrefix, &writerWg)
	}
	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, resultsCh, writeCh, &routerWg)

	it := vulnBucket.Objects(ctx, &storage.Query{Prefix: "all/pb/"})
	prevPrefix := ""
MainLoop:
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
		select {
		case objCh <- vulnBucket.Object(attrs.Name):
		case <-ctx.Done():
			break MainLoop
		}
	}

	close(objCh)
	downloaderWg.Wait()
	close(resultsCh)
	routerWg.Wait()
	close(writeCh)
	writerWg.Wait()

	if ctx.Err() != nil {
		logger.Fatal("exporter cancelled")
	}
}

func ecosystemRouter(ctx context.Context, inCh <-chan *osvschema.Vulnerability, writeCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	workers := make(map[string]*ecosystemWorker)
	var workersWg sync.WaitGroup

	workersWg.Add(1)
	allWorker := newAllWorker(ctx, writeCh, &workersWg)

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
		ecoNames := make([]string, 0, len(ecosystems))
		for eco := range ecosystems {
			ecoNames = append(ecoNames, eco)
			worker, ok := workers[eco]
			if !ok {
				workersWg.Add(1)
				worker = newEcosystemWorker(ctx, eco, writeCh, &workersWg)
				workers[eco] = worker
			}
			worker.ch <- vuln
		}
		allWorker.ch <- vulnAndEcos{Vulnerability: vuln, ecosystems: ecoNames}
	}

	for _, worker := range workers {
		worker.Finish()
	}
	allWorker.Finish()
	workersWg.Wait()
}
