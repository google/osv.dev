// Package main converts CVEs to OSV format in bulk.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/osv/vulnfeeds/conversion/cve5"
	"github.com/google/osv/vulnfeeds/conversion/writer"
	"github.com/google/osv/vulnfeeds/gcs-tools"
	"github.com/google/osv/vulnfeeds/models"
	"github.com/google/osv/vulnfeeds/utility/logger"
)

const defaultStartYear = "2022"

var (
	repoDir        = flag.String("cve5-repo", "cvelistV5", "CVEListV5 directory path")
	localOutputDir = flag.String("out-dir", "cve5", "Path to output results.")
	startYear      = flag.String("start-year", defaultStartYear, "The first in scope year to process.")
	workers        = flag.Int("workers", 10, "The number of concurrent workers to use for processing CVEs.")
	gcsWorkers     = flag.Int("gcs-workers", 30, "The number of concurrent workers to use for GCS uploads.")
	cnaDenyList    = flag.String("cna-denylist", "", "A comma-separated list of CNAs to skip. If not provided, defaults to cna_denylist.txt.")
	rejectFailed   = flag.Bool("reject-failed", false, "If set, OSV records with a failed conversion outcome will not be generated.")
	uploadToGCS    = flag.Bool("upload-to-gcs", false, "If true, upload to GCS bucket instead of writing to local disk.")
	outputBucket   = flag.String("output-bucket", "osv-test-cve-osv-conversion", "The GCS bucket to write to.")
	gcsPrefix      = flag.String("gcs-prefix", "cve5-osv", "The prefix within the GCS bucket.")
)

//go:embed cna_denylist.txt
var cnaDenylistData []byte

func main() {
	flag.Parse()
	logger.InitGlobalLogger()
	defer logger.Close()

	startYearInt, err := strconv.Atoi(*startYear)
	defaultStartYearInt, _ := strconv.Atoi(defaultStartYear)
	isPartial := false
	if err != nil {
		logger.Error("Invalid start-year, assuming partial", slog.String("start-year", *startYear))
		isPartial = true
	} else if startYearInt > defaultStartYearInt {
		isPartial = true
	}

	if isPartial {
		logger.Info("Partial run detected (start-year > " + defaultStartYear + "), will skip files.txt upload")
	}

	logger.Info("Commencing CVE to OSV conversion run")
	if err := os.MkdirAll(*localOutputDir, 0755); err != nil {
		logger.Fatal("Failed to create local output directory", slog.Any("err", err))
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var cnaList []string
	if *cnaDenyList != "" {
		cnaList = strings.Split(*cnaDenyList, ",")
	} else {
		for _, cna := range strings.Split(string(cnaDenylistData), "\n") {
			cna = strings.TrimSpace(cna)
			if cna != "" {
				cnaList = append(cnaList, cna)
			}
		}
	}

	var gcsHelper *gcs.Helper
	ctx := context.Background()
	if *uploadToGCS {
		var err error
		gcsHelper, err = gcs.InitUploadPool(ctx, *gcsWorkers, *outputBucket)
		if err != nil {
			logger.Fatal("Failed to initialize GCS upload pool", slog.Any("err", err))
		}
		logger.Info("GCS Upload Pool initialized", slog.String("bucket", *outputBucket))
	}

	outputFilesChan := make(chan string)
	var collectorWg sync.WaitGroup
	var outputFiles []string
	collectorWg.Add(1)
	go func() {
		defer collectorWg.Done()
		for f := range outputFilesChan {
			outputFiles = append(outputFiles, f)
		}
	}()

	// Start the worker pool.
	for range *workers {
		wg.Add(1)
		go worker(&wg, jobs, gcsHelper, *localOutputDir, cnaList, *rejectFailed, outputFilesChan)
	}

	// Discover files and send them to the workers.
	logger.Info("Starting conversion of CVEs...")
	currentYear := time.Now().Year()

	for year := startYearInt; year <= currentYear; year++ {
		year := strconv.Itoa(year)
		yearDir := filepath.Join(*repoDir, "cves", year)
		if _, err := os.Stat(yearDir); os.IsNotExist(err) {
			logger.Info("Directory for year not found, skipping", slog.String("year", year))
			continue
		}

		logger.Info("Processing CVEs for year", slog.String("year", year))
		err := filepath.Walk(yearDir, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				logger.Info("Error walking directory for year", slog.String("year", year), slog.Any("err", err))
				return err
			}
			if !info.IsDir() && strings.HasSuffix(info.Name(), ".json") {
				jobs <- path
			}

			return nil
		})
		if err != nil {
			logger.Info("Error walking directory for year", slog.String("year", year), slog.Any("err", err))
		}
	}

	close(jobs)
	wg.Wait()
	close(outputFilesChan)
	collectorWg.Wait()

	if *uploadToGCS && gcsHelper != nil {
		gcsHelper.CloseAndWait()
		if !isPartial {
			logger.Info("Uploading output file list to GCS...")
			if err := gcs.UploadFileList(ctx, *outputBucket, *gcsPrefix, outputFiles); err != nil {
				logger.Error("Failed to upload output file list", slog.Any("err", err))
			}
		} else {
			logger.Info("Skipping files.txt upload due to partial run")
		}
	}

	logger.Info("CVE5 Conversion run complete")
}

// worker is a function that processes CVE files from the jobs channel.
func worker(wg *sync.WaitGroup, jobs <-chan string, gcsHelper *gcs.Helper, outDir string, cnas []string, rejectFailed bool, outputFilesChan chan<- string) {
	defer wg.Done()
	for cvePath := range jobs {
		data, err := os.ReadFile(cvePath)
		if err != nil {
			logger.Info("Failed to read file", slog.String("path", cvePath), slog.Any("err", err))
			continue
		}

		var cve models.CVE5
		if err := json.Unmarshal(data, &cve); err != nil {
			logger.Info("Failed to unmarshal JSON", slog.String("path", cvePath), slog.Any("err", err))
			continue
		}

		if slices.Contains(cnas, cve.Metadata.AssignerShortName) || cve.Metadata.State != "PUBLISHED" {
			continue
		}
		cveID := cve.Metadata.CVEID
		logger.Info("Processing "+string(cveID), slog.String("cve", string(cveID)))

		sourceLink := ""
		baseDirCVEList := "cves/" // The base folder for the CVEListV5 repository.
		idx := strings.Index(cvePath, baseDirCVEList)
		if idx != -1 {
			relPath := cvePath[idx:]
			sourceLink = "https://github.com/CVEProject/cvelistV5/tree/main/" + relPath
		}

		if gcsHelper != nil {
			vuln, metrics := cve5.CVEToOSV(cve, sourceLink)
			if rejectFailed && metrics.Outcome != models.Successful {
				logger.Info("Rejecting failed OSV record", slog.String("cve", string(cveID)), slog.String("outcome", metrics.Outcome.String()))
			} else {
				logger.Info("Queueing OSV record for "+string(cveID), slog.String("cve", string(cveID)))
				if err := writer.UploadVulnIfChangedAsync(gcsHelper, *gcsPrefix, vuln.Vulnerability); err != nil {
					logger.Error("Failed to queue vulnerability upload", slog.String("cve", string(cveID)), slog.Any("err", err))
				} else {
					outputFilesChan <- path.Join(*gcsPrefix, string(cveID)+".json")
				}

				if err := writer.UploadMetricsToGCSAsync(gcsHelper, *gcsPrefix, cveID, metrics); err != nil {
					logger.Error("Failed to queue metrics upload", slog.String("cve", string(cveID)), slog.Any("err", err))
				}
			}

			// Always write metrics locally for outcomes CSV auditing
			metricsFile, err := writer.CreateMetricsFile(cveID, outDir)
			if err == nil {
				err = writer.WriteMetricsFile(metrics, metricsFile)
				if err != nil {
					logger.Error("Failed to write metrics file", slog.String("cve", string(cveID)), slog.Any("err", err))
				}
				metricsFile.Close()
			}
		} else {
			osvFile, errCVE := writer.CreateOSVFile(cveID, outDir)
			metricsFile, errMetrics := writer.CreateMetricsFile(cveID, outDir)
			if errCVE != nil || errMetrics != nil {
				logger.Fatal("File failed to be created for CVE", slog.String("cve", string(cveID)))
			}

			// Perform the conversion and export the results.
			metrics, err := cve5.ConvertAndExportCVEToOSV(cve, osvFile, metricsFile, sourceLink)
			if err != nil {
				logger.Warn("Failed to generate an OSV record", slog.String("cve", string(cveID)), slog.Any("err", err))
			} else {
				if rejectFailed && metrics.Outcome != models.Successful {
					logger.Info("Rejecting failed OSV record", slog.String("cve", string(cveID)), slog.String("outcome", metrics.Outcome.String()))
					osvFile.Close()
					os.Remove(osvFile.Name())
				} else {
					logger.Info("Generated OSV record for "+string(cveID), slog.String("cve", string(cveID)), slog.String("cna", cve.Metadata.AssignerShortName), slog.String("outcome", metrics.Outcome.String()))
				}
			}

			metricsFile.Close()
			osvFile.Close()
		}
	}
}
