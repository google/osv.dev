// Package main runs the exporter, exporting the whole OSV database to the GCS bucket.
// See the README.md for more details.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"go.opentelemetry.io/otel"
	"google.golang.org/api/option"
)

const gcsProtoPrefix = "all/pb/"

// main is the entry point for the exporter. It initializes the GCS clients,
// sets up the worker pipeline, and starts the GCS object iteration.
func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	ctx, stopSignal := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignal()

	ctx, span := otel.Tracer("exporter").Start(ctx, "exporter")
	defer span.End()

	outBucketName := flag.String("bucket", "osv-test-vulnerabilities", "Output bucket or directory name. If -local is true, this is a local path; otherwise, it's a GCS bucket name.")
	vulnBucketName := flag.String("osv-vulns-bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "GCS bucket to read vulnerability protobufs from. Can also be set with the OSV_VULNERABILITIES_BUCKET environment variable.")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "If false, writes the output to a local directory specified by -bucket instead of a GCS bucket.")
	numWorkers := flag.Int("workers", 1000, "The total number of concurrent workers to use for downloading from GCS and writing the output.")
	breakdownPrefixesStr := flag.String("breakdown-prefixes", "", "Comma-separated list of prefix breakdowns for parallel GCS object listing. Defaults to A-Z if empty.")

	flag.Parse()

	logger.InfoContext(ctx, "exporter starting",
		slog.String("bucket", *outBucketName),
		slog.String("osv-vulns-bucket", *vulnBucketName),
		slog.Bool("upload-to-gcs", *uploadToGCS),
		slog.Int("workers", *numWorkers),
		slog.String("breakdown-prefixes", *breakdownPrefixesStr))

	if *vulnBucketName == "" {
		logger.FatalContext(ctx, "OSV_VULNERABILITIES_BUCKET must be set")
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	storageClient, err := storage.NewClient(ctx, option.WithTelemetryDisabled())
	if err != nil {
		logger.FatalContext(ctx, "failed to create storage client", slog.Any("err", err))
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
	// 1. The main goroutine lists GCS objects and sends them to `gcsPathToDownloaderCh`.
	// 2. A pool of `downloader` workers receive GCS objects, downloads and unmarshals them into
	//    OSV vulnerabilities, and send them to `downloaderToRouterCh`.
	// 3. The `ecosystemRouter` receives vulnerabilities and dispatches them. It creates a new
	//    `ecosystemWorker` for each new ecosystem, and sends all vulnerabilities to a single
	//    `allEcosystemWorker`.
	// 4. The `ecosystemWorker`s and the `allEcosystemWorker` process the vulnerabilities and
	//    generate the final files, sending the data to be written to `routerToWriteCh`.
	// 5. A pool of `writer` workers receive the file data and write it to the output.
	gcsPathToDownloaderCh := make(chan string, 100)
	downloaderToRouterCh := make(chan *osvschema.Vulnerability, 100)
	routerToWriteCh := make(chan writeMsg, 100)

	var breakdownPrefixes []string
	if *breakdownPrefixesStr != "" {
		for _, p := range strings.Split(*breakdownPrefixesStr, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				breakdownPrefixes = append(breakdownPrefixes, p)
			}
		}
	}
	// Fall back to simple A-Z prefixes
	if len(breakdownPrefixes) == 0 {
		for ch := 'A'; ch <= 'Z'; ch++ {
			breakdownPrefixes = append(breakdownPrefixes, string(ch))
		}
	}

	var downloaderWg sync.WaitGroup
	for range *numWorkers / 2 {
		downloaderWg.Add(1)
		go downloader(ctx, vulnClient, gcsPathToDownloaderCh, downloaderToRouterCh, &downloaderWg)
	}

	var writerWg sync.WaitGroup
	for range *numWorkers / 2 {
		writerWg.Add(1)
		go writer(ctx, cancel, routerToWriteCh, outClient, outPrefix, &writerWg)
	}
	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, downloaderToRouterCh, routerToWriteCh, &routerWg)

MainLoop:
	for objName, err := range vulnClient.ObjectsFast(ctx, gcsProtoPrefix, breakdownPrefixes) {
		if err != nil {
			logger.FatalContext(ctx, "failed to list objects", slog.Any("err", err))
		}
		select {
		case gcsPathToDownloaderCh <- objName:
		case <-ctx.Done():
			break MainLoop
		}
	}

	close(gcsPathToDownloaderCh)
	downloaderWg.Wait()
	close(downloaderToRouterCh)
	routerWg.Wait()
	close(routerToWriteCh)
	writerWg.Wait()

	if ctx.Err() != nil {
		logger.FatalContext(ctx, "exporter cancelled")
	}
	logger.InfoContext(ctx, "export completed successfully")
}

// ecosystemRouter receives vulnerabilities from inCh and fans them out to the
// appropriate ecosystemWorker. It creates workers on-demand for each new
// ecosystem encountered. It also sends every vulnerability to the allEcosystemWorker.
func ecosystemRouter(ctx context.Context, inCh <-chan *osvschema.Vulnerability, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.InfoContext(ctx, "ecosystem router starting")
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
		logger.InfoContext(ctx, "ecosystem router finished, all vulnerabilities dispatched", slog.Int("total_vulnerabilities", vulnCounter))
	} else {
		logger.InfoContext(ctx, "ecosystem router cancelled", slog.Any("err", ctx.Err()))
	}
}
