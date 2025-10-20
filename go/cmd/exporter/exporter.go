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

const gcsProtoPrefix = "all/pb/"

func main() {
	logger.InitGlobalLogger()

	outBucketName := flag.String("bucket", "osv-vulnerabilities", "Output bucket or directory name. If -local is true, this is a local path; otherwise, it's a GCS bucket name.")
	vulnBucketName := flag.String("osv_vulns_bucket", os.Getenv("OSV_VULNERABILITIES_BUCKET"), "GCS bucket to read vulnerability protobufs from. Can also be set with the OSV_VULNERABILITIES_BUCKET environment variable.")
	local := flag.Bool("local", true, "If true, writes the output to a local directory specified by -bucket instead of a GCS bucket.")
	numWorkers := flag.Int("num_workers", 200, "The total number of concurrent workers to use for downloading from GCS and writing the output.")

	flag.Parse()

	logger.Info("exporter starting",
		slog.String("bucket", *outBucketName),
		slog.String("osv_vulns_bucket", *vulnBucketName),
		slog.Bool("local", *local),
		slog.Int("num_workers", *numWorkers))

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
	gcsObjToDownloaderCh := make(chan *storage.ObjectHandle)
	downloaderToRouterCh := make(chan *osvschema.Vulnerability)
	routerToWriteCh := make(chan writeMsg)

	var downloaderWg sync.WaitGroup
	for range *numWorkers / 2 {
		downloaderWg.Add(1)
		go downloader(ctx, gcsObjToDownloaderCh, downloaderToRouterCh, &downloaderWg)
	}

	var writerWg sync.WaitGroup
	for range *numWorkers / 2 {
		writerWg.Add(1)
		go writer(ctx, cancel, routerToWriteCh, outBucket, outPrefix, &writerWg)
	}
	var routerWg sync.WaitGroup
	routerWg.Add(1)
	go ecosystemRouter(ctx, downloaderToRouterCh, routerToWriteCh, &routerWg)

	it := vulnBucket.Objects(ctx, &storage.Query{Prefix: gcsProtoPrefix})
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
		// Only log when we see a new ID prefix (i.e. roughly once per data source)
		prefix := filepath.Base(attrs.Name)
		prefix, _, _ = strings.Cut(prefix, "-")
		if prefix != prevPrefix {
			logger.Info("iterating vulnerabilities", slog.String("now_at", attrs.Name))
			prevPrefix = prefix
		}
		select {
		case gcsObjToDownloaderCh <- vulnBucket.Object(attrs.Name):
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

func ecosystemRouter(ctx context.Context, inCh <-chan *osvschema.Vulnerability, outCh chan<- writeMsg, wg *sync.WaitGroup) {
	defer wg.Done()
	logger.Info("ecosystem router starting")
	workers := make(map[string]*ecosystemWorker)
	var workersWg sync.WaitGroup
	vulnCounter := 0

	allEcosystemWorker := newAllEcosystemWorker(ctx, outCh, &workersWg)

	for vuln := range inCh {
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
			worker.inCh <- vuln
		}
		allEcosystemWorker.inCh <- vulnAndEcos{Vulnerability: vuln, ecosystems: ecoNames}
	}

	for _, worker := range workers {
		worker.Finish()
	}
	allEcosystemWorker.Finish()
	workersWg.Wait()
	logger.Info("ecosystem router finished, all vulnerabilities dispatched", slog.Int("total_vulnerabilities", vulnCounter))
}
