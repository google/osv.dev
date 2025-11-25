// Package main runs the exporter, exporting the whole OSV database to the GCS bucket.
// See the README.md for more details.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
)

const gcsProtoPrefix = "all/pb/"

// main is the entry point for the exporter. It initializes the GCS clients,
// sets up the worker pipeline, and starts the GCS object iteration.
func main() {
	logger.InitGlobalLogger()

	outBucketName := flag.String("bucket", "osv-test-vulnerabilities", "Output bucket or directory name. If -local is true, this is a local path; otherwise, it's a GCS bucket name.")
	vulnBucketName := flag.String("osv_vulns_bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "GCS bucket to read vulnerability protobufs from. Can also be set with the OSV_VULNERABILITIES_BUCKET environment variable.")
	uploadToGCS := flag.Bool("uploadToGCS", false, "If false, writes the output to a local directory specified by -bucket instead of a GCS bucket.")
	numWorkers := flag.Int("num_workers", 200, "The total number of concurrent workers to use for downloading from GCS and writing the output.")

	flag.Parse()

	logger.Info("exporter starting",
		slog.String("bucket", *outBucketName),
		slog.String("osv_vulns_bucket", *vulnBucketName),
		slog.Bool("uploadToGCS", *uploadToGCS),
		slog.Int("num_workers", *numWorkers))

	if *vulnBucketName == "" {
		logger.Fatal("OSV_VULNERABILITIES_BUCKET must be set")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	storageClient, err := storage.NewClient(ctx)
	if err != nil {
		logger.Fatal("failed to create storage client", slog.Any("err", err))
	}
	defer storageClient.Close()

	vulnClient := clients.NewGCSClient(storageClient, *vulnBucketName)

	var outClient clients.CloudStorage
	var outPrefix string
	if *outBucketName != "" && *uploadToGCS { // Added *uploadToGCS check to match original logic
		outClient = clients.NewGCSClient(storageClient, *outBucketName)
	} else {
		outPrefix = *outBucketName
	}

	// The exporter uses a pipeline of channels and worker pools. The data flow is as follows:
	// 1. The main goroutine lists GCS objects and sends them to `gcsObjToDownloaderCh`.
	// 2. A pool of `downloader` workers receive GCS objects, downloads and unmarshals them into
	//    OSV vulnerabilities, and send them to `downloaderToRouterCh`.
	// 3. The `ecosystemRouter` receives vulnerabilities and dispatches them. It creates a new
	//    `ecosystemWorker` for each new ecosystem, and sends all vulnerabilities to a single
	//    `allEcosystemWorker`.
	// 4. The `ecosystemWorker`s and the `allEcosystemWorker` process the vulnerabilities and
	//    generate the final files, sending the data to be written to `routerToWriteCh`.
	// 5. A pool of `writer` workers receive the file data and write it to the output.
	gcsObjToDownloaderCh := make(chan string)
	downloaderToRouterCh := make(chan *osvschema.Vulnerability)
	routerToWriteCh := make(chan writeMsg)

	var downloaderWg sync.WaitGroup
	for range *numWorkers / 2 {
		downloaderWg.Add(1)
		go downloader(ctx, vulnClient, gcsObjToDownloaderCh, downloaderToRouterCh, &downloaderWg)
	}

	var writerWg sync.WaitGroup
	for range *numWorkers / 2 {
		writerWg.Add(1)
		go writer(ctx, cancel, routerToWriteCh, outClient, outPrefix, &writerWg)
	}
	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, downloaderToRouterCh, routerToWriteCh, &routerWg)

	prevPrefix := ""
MainLoop:
	for path, err := range vulnClient.Objects(ctx, gcsProtoPrefix) {
		if err != nil {
			logger.Error("failed to list objects", slog.Any("err", err))
			break
		}
		// Only log when we see a new ID prefix (i.e. roughly once per data source)
		prefix := filepath.Base(path)
		prefix, _, _ = strings.Cut(prefix, "-")
		if prefix != prevPrefix {
			logger.Info("iterating vulnerabilities", slog.String("now_at", path))
			prevPrefix = prefix
		}
		select {
		case gcsObjToDownloaderCh <- path:
		case <-ctx.Done():
			break MainLoop
		}
	}

	close(gcsObjToDownloaderCh)
	downloaderWg.Wait()
	close(downloaderToRouterCh)
	routerWg.Wait()
	close(routerToWriteCh)
	writerWg.Wait()

	if ctx.Err() != nil {
		logger.Fatal("exporter cancelled")
	}
	logger.Info("export completed successfully")
}

// ecosystemRouter receives vulnerabilities from inCh and fans them out to the
// appropriate ecosystemWorker. It creates workers on-demand for each new
// ecosystem encountered. It also sends every vulnerability to the allEcosystemWorker.
func ecosystemRouter(ctx context.Context, inCh <-chan *osvschema.Vulnerability, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("ecosystem router starting")
	workers := make(map[string]*ecosystemWorker)
	var workersWg sync.WaitGroup
	vulnCounter := 0

	allEcosystemWorker := newAllEcosystemWorker(ctx, outCh, &workersWg)

RouterLoop:
	for {
		var vuln *osvschema.Vulnerability
		var ok bool
		select {
		case <-ctx.Done():
			break RouterLoop
		case vuln, ok = <-inCh:
			if !ok {
				break RouterLoop
			}
		}
		vulnCounter++
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
				worker = newEcosystemWorker(ctx, eco, outCh, &workersWg)
				workers[eco] = worker
			}
			select {
			case worker.inCh <- vuln:
			case <-ctx.Done():
				break RouterLoop
			}
		}
		select {
		case allEcosystemWorker.inCh <- vulnAndEcos{Vulnerability: vuln, ecosystems: ecoNames}:
		case <-ctx.Done():
			break RouterLoop
		}
	}

	for _, worker := range workers {
		worker.Finish()
	}
	allEcosystemWorker.Finish()
	workersWg.Wait()
	if ctx.Err() == nil {
		logger.Info("ecosystem router finished, all vulnerabilities dispatched", slog.Int("total_vulnerabilities", vulnCounter))
	} else {
		logger.Info("ecosystem router cancelled", slog.Any("err", ctx.Err()))
	}
}
