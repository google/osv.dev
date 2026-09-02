// Package main runs the exporter, exporting the whole OSV database to the GCS bucket.
// See the README.md for more details.
package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/sharding"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/osv/clients"
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

	defaultScratchDir := os.Getenv("SCRATCH_DIR")
	if defaultScratchDir == "" {
		defaultScratchDir = filepath.Join(os.TempDir(), "osv-exporter-scratch")
	}

	outBucketName := flag.String("bucket", "osv-test-vulnerabilities", "Output bucket or directory name. If -local is true, this is a local path; otherwise, it's a GCS bucket name.")
	vulnBucketName := flag.String("osv-vulns-bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "GCS bucket to read vulnerability protobufs from. Can also be set with the OSV_VULNERABILITIES_BUCKET environment variable.")
	uploadToGCS := flag.Bool("upload-to-gcs", false, "If false, writes the output to a local directory specified by -bucket instead of a GCS bucket.")
	numWorkers := flag.Int("workers", 1000, "The total number of concurrent workers to use for downloading from GCS and writing the output.")
	breakdownPrefixesStr := flag.String("breakdown-prefixes", "", "Comma-separated list of prefix breakdowns for parallel GCS object listing.")
	scratchDirFlag := flag.String("scratch-dir", defaultScratchDir, "Directory to stage temporary JSON and zip files.")
	cleanUpScratchDir := flag.Bool("cleanup-scratch-dir", false, "Whether to delete the temporary scratch directory on exit. Defaults to false.")

	flag.Parse()

	scratchDir := *scratchDirFlag
	if err := os.MkdirAll(scratchDir, 0755); err != nil {
		logger.FatalContext(ctx, "failed to create scratch directory", slog.String("dir", scratchDir), slog.Any("err", err))
	}
	scratchDir, err := os.MkdirTemp(scratchDir, "osv-exporter-*")
	if err != nil {
		logger.FatalContext(ctx, "failed to create temp directory in scratch dir", slog.String("dir", scratchDir), slog.Any("err", err))
	}
	if *cleanUpScratchDir {
		defer os.RemoveAll(scratchDir)
	}

	logger.InfoContext(ctx, "exporter starting",
		slog.String("bucket", *outBucketName),
		slog.String("osv-vulns-bucket", *vulnBucketName),
		slog.Bool("upload-to-gcs", *uploadToGCS),
		slog.Int("workers", *numWorkers),
		slog.Bool("cleanup-scratch-dir", *cleanUpScratchDir),
		slog.String("breakdown-prefixes", *breakdownPrefixesStr),
		slog.String("scratch-dir", scratchDir))

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
	// 1. The main goroutine lists GCS objects and sends them to `gcsPathToProcessorCh`.
	// 2. A pool of `downloadThenProcessor` workers receive GCS objects, downloads, unmarshals,
	//    marshals to JSON, saves to scratch disk, queues individual JSON writes to `writeCh`,
	//    and sends metadata to `processorToRouterCh`.
	// 3. The `ecosystemRouter` receives metadata and dispatches it. It creates a new
	//    `ecosystemWorker` for each new ecosystem, and sends all vulnerabilities to a single
	//    `allEcosystemWorker`.
	// 4. The `ecosystemWorker`s and the `allEcosystemWorker` aggregate metadata and generate the
	//    final zip, csv, and ecosystems.txt files, sending the write requests to `writeCh`.
	// 5. A pool of `writer` workers receive the file data and write it to the output.
	gcsPathToProcessorCh := make(chan string, 100)
	processorToRouterCh := make(chan processedVuln, 100)
	writeCh := make(chan writeMsg, 100)

	breakdownPrefixes := sharding.ExpandBreakdownPrefixes(*breakdownPrefixesStr)

	var processorWg sync.WaitGroup
	for range *numWorkers / 2 {
		processorWg.Add(1)
		go downloadThenProcessor(ctx, cancel, vulnClient, scratchDir, gcsPathToProcessorCh, processorToRouterCh, writeCh, &processorWg)
	}

	var writerWg sync.WaitGroup
	for range *numWorkers / 2 {
		writerWg.Add(1)
		go writer(ctx, cancel, writeCh, outClient, outPrefix, &writerWg)
	}
	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, processorToRouterCh, writeCh, scratchDir, &routerWg)

	logDiskUsage(ctx, scratchDir, "startup")

MainLoop:
	for objName, err := range vulnClient.ObjectsFast(ctx, gcsProtoPrefix, breakdownPrefixes) {
		if err != nil {
			logger.FatalContext(ctx, "failed to list objects", slog.Any("err", err))
		}
		select {
		case gcsPathToProcessorCh <- objName:
		case <-ctx.Done():
			break MainLoop
		}
	}

	close(gcsPathToProcessorCh)
	processorWg.Wait()
	logDiskUsage(ctx, scratchDir, "downloads_complete")
	close(processorToRouterCh)
	routerWg.Wait()
	logDiskUsage(ctx, scratchDir, "export_complete")
	close(writeCh)
	writerWg.Wait()

	if ctx.Err() != nil {
		logger.FatalContext(ctx, "exporter cancelled")
	}
	logger.InfoContext(ctx, "export completed successfully")
}

// logDiskUsage logs the scratch filesystem space metrics.
func logDiskUsage(ctx context.Context, dir string, stage string) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(dir, &stat); err != nil {
		logger.WarnContext(ctx, "failed to get scratch disk usage", slog.String("dir", dir), slog.Any("err", err))
		return
	}
	if stat.Bsize <= 0 || stat.Blocks == 0 {
		return
	}

	const gib = 1024 * 1024 * 1024
	blockSize := float64(stat.Bsize)
	usedGB := float64(stat.Blocks-stat.Bfree) * blockSize / gib
	totalGB := float64(stat.Blocks) * blockSize / gib
	freeGB := float64(stat.Bavail) * blockSize / gib

	logger.InfoContext(ctx, "scratch disk usage",
		slog.String("stage", stage),
		slog.Float64("used_gb", usedGB),
		slog.Float64("free_gb", freeGB),
		slog.Float64("total_gb", totalGB),
		slog.Float64("used_pct", usedGB/totalGB*100),
	)
}

// ecosystemRouter receives processed vulnerabilities from inCh and fans them out to the
// appropriate ecosystemWorker. It creates workers on-demand for each new
// ecosystem encountered. It also sends every vulnerability to the allEcosystemWorker.
func ecosystemRouter(ctx context.Context, inCh <-chan processedVuln, outCh chan<- writeMsg, scratchDir string, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.InfoContext(ctx, "ecosystem router starting")
	workers := make(map[string]*ecosystemWorker)
	var workersWg sync.WaitGroup
	vulnCounter := 0
	var vanirVulnIDs []string

	allEcosystemWorker := newAllEcosystemWorker(ctx, scratchDir, outCh, &workersWg)

RouterLoop:
	for {
		var vuln processedVuln
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

		if vuln.hasVanir {
			vanirVulnIDs = append(vanirVulnIDs, vuln.meta.id)
		}

		for _, eco := range vuln.ecosystems {
			worker, ok := workers[eco]
			if !ok {
				worker = newEcosystemWorker(ctx, eco, scratchDir, outCh, &workersWg)
				workers[eco] = worker
			}
			select {
			case worker.inCh <- vuln.meta:
			case <-ctx.Done():
				break RouterLoop
			}
		}
		select {
		case allEcosystemWorker.inCh <- vulnAndEcos{meta: vuln.meta, ecosystems: vuln.ecosystems}:
		case <-ctx.Done():
			break RouterLoop
		}
	}

	for _, worker := range workers {
		worker.Finish()
	}
	allEcosystemWorker.Finish()
	workersWg.Wait()

	if len(vanirVulnIDs) > 0 && ctx.Err() == nil {
		writeVanir(ctx, vanirVulnIDs, outCh, scratchDir)
	}

	if ctx.Err() == nil {
		logger.InfoContext(ctx, "ecosystem router finished, all vulnerabilities dispatched", slog.Int("total_vulnerabilities", vulnCounter))
	} else {
		logger.InfoContext(ctx, "ecosystem router cancelled", slog.Any("err", ctx.Err()))
	}
}
