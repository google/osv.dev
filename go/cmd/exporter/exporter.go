package main

import (
	"context"
	"flag"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/sharding"
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

	flag.Parse()

	scratchDir := *scratchDirFlag
	if err := os.MkdirAll(scratchDir, 0755); err != nil {
		logger.FatalContext(ctx, "failed to create scratch directory", slog.String("dir", scratchDir), slog.Any("err", err))
	}
	stagingDir, err := os.MkdirTemp(scratchDir, "osv-exporter-staging-*")
	if err != nil {
		logger.FatalContext(ctx, "failed to create staging directory in scratch dir", slog.String("dir", scratchDir), slog.Any("err", err))
	}
	defer os.RemoveAll(stagingDir)

	logger.InfoContext(ctx, "exporter starting",
		slog.String("bucket", *outBucketName),
		slog.String("osv-vulns-bucket", *vulnBucketName),
		slog.Bool("upload-to-gcs", *uploadToGCS),
		slog.Int("workers", *numWorkers),
		slog.String("breakdown-prefixes", *breakdownPrefixesStr),
		slog.String("scratch-dir", scratchDir),
		slog.String("staging-dir", stagingDir))

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

	breakdownPrefixes := sharding.ExpandBreakdownPrefixes(*breakdownPrefixesStr)

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
	go ecosystemRouter(ctx, downloaderToRouterCh, routerToWriteCh, stagingDir, &routerWg)

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
func ecosystemRouter(ctx context.Context, inCh <-chan *osvschema.Vulnerability, outCh chan<- writeMsg, scratchDir string, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.InfoContext(ctx, "ecosystem router starting")
	workers := make(map[string]*ecosystemWorker)
	var workersWg sync.WaitGroup
	vulnCounter := 0
	var vanirVulns []vulnMeta

	vulnsDir := filepath.Join(scratchDir, "vulns")
	if err := os.MkdirAll(vulnsDir, 0755); err != nil {
		logger.FatalContext(ctx, "failed to create scratch vulns directory", slog.Any("err", err))
	}

	allEcosystemWorker := newAllEcosystemWorker(ctx, scratchDir, outCh, &workersWg)

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

		// Marshal JSON ONCE for this vulnerability.
		b, err := marshalToJSON(vuln)
		if err != nil {
			logger.ErrorContext(ctx, "failed to marshal vulnerability to json", slog.String("id", vuln.GetId()), slog.Any("err", err))
			continue
		}

		// Cache to local scratch disk for later ZIP generation.
		localPath := filepath.Join(vulnsDir, vuln.GetId()+".json")
		if err := os.WriteFile(localPath, b, 0600); err != nil {
			logger.ErrorContext(ctx, "failed to write cached vulnerability to disk", slog.String("id", vuln.GetId()), slog.Any("err", err))
			continue
		}

		meta := vulnMeta{
			id:        vuln.GetId(),
			modified:  vuln.GetModified().AsTime(),
			localPath: localPath,
		}

		// Check for Vanir signatures
		for _, aff := range vuln.GetAffected() {
			spec := aff.GetDatabaseSpecific()
			if _, ok := spec.GetFields()["vanir_signatures"]; ok {
				vanirVulns = append(vanirVulns, meta)
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
				worker = newEcosystemWorker(ctx, eco, scratchDir, outCh, &workersWg)
				workers[eco] = worker
			}
			select {
			case worker.inCh <- meta:
			case <-ctx.Done():
				break RouterLoop
			}
			select {
			case outCh <- writeMsg{path: filepath.Join(eco, vuln.GetId()) + ".json", mimeType: "application/json", data: b}:
			case <-ctx.Done():
				break RouterLoop
			}
		}
		select {
		case allEcosystemWorker.inCh <- vulnAndEcos{meta: meta, ecosystems: ecoNames}:
		case <-ctx.Done():
			break RouterLoop
		}
	}

	for _, worker := range workers {
		worker.Finish()
	}
	allEcosystemWorker.Finish()
	workersWg.Wait()

	if len(vanirVulns) > 0 && ctx.Err() == nil {
		writeVanir(ctx, vanirVulns, outCh, scratchDir)
	}

	if ctx.Err() == nil {
		logger.InfoContext(ctx, "ecosystem router finished, all vulnerabilities dispatched", slog.Int("total_vulnerabilities", vulnCounter))
	} else {
		logger.InfoContext(ctx, "ecosystem router cancelled", slog.Any("err", ctx.Err()))
	}
}
