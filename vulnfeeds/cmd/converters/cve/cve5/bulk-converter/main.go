// Package main converts CVEs to OSV format in bulk.
package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/osv.dev/vulnfeeds/conversion"
	"github.com/google/osv.dev/vulnfeeds/conversion/cve5"
	"github.com/google/osv.dev/vulnfeeds/conversion/writer"
	"github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/git"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
)

const defaultStartYear = "2022"

var (
	// Input & filtering flags.
	repoDir      = flag.String("cve5-repo", "cvelistV5", "CVEListV5 directory path")
	startYear    = flag.String("start-year", defaultStartYear, "The first in scope year to process.")
	cnaDenyList  = flag.String("cna-denylist", "", "A comma-separated list of CNAs to skip. If not provided, defaults to cna_denylist.txt.")
	rejectFailed = flag.Bool("reject-failed", false, "If set, OSV records with a failed conversion outcome will not be generated.")

	// Local output directory flags.
	localOutputDir = flag.String("out-dir", "cve5", "Path to output results.")
	metricsDir     = flag.String("metrics-dir", "", "Path to output metrics JSON files (defaults to out-dir).")
	outcomesDir    = flag.String("outcomes-dir", "", "Path to output conversion outcomes CSV file (defaults to metrics-dir or out-dir).")
	csvDir         = flag.String("csv-dir", "", "Alias for outcomes-dir.")
	outputMetrics  = flag.Bool("output-metrics", true, "If true, output the metrics information about the conversion")

	// Concurrency & worker flags.
	workers    = flag.Int("workers", 10, "The number of concurrent workers to use for processing CVEs.")
	gcsWorkers = flag.Int("gcs-workers", 30, "The number of concurrent workers to use for GCS uploads.")

	// GCS upload flags.
	uploadToGCS       = flag.Bool("upload-to-gcs", false, "If true, upload to GCS bucket instead of writing to local disk.")
	outputBucket      = flag.String("output-bucket", "osv-test-cve-osv-conversion", "The GCS bucket to write to.")
	gcsPrefix         = flag.String("gcs-prefix", "cve5-osv", "The prefix within the GCS bucket.")
	gcsMetricsPrefix  = flag.String("gcs-metrics-prefix", "metadata/cve5/metrics", "The prefix for metrics JSON within the GCS bucket.")
	gcsOutcomesPrefix = flag.String("gcs-outcomes-prefix", "metadata/cve5/outcomes", "The prefix for outcomes CSV within the GCS bucket.")
)

var (
	totalConversionsCount      atomic.Uint64
	successfulConversionsCount atomic.Uint64
)

//go:embed cna_denylist.txt
var cnaDenylistData []byte

func main() {
	flag.Parse()
	logger.InitGlobalLogger()
	defer logger.Close()

	actualMetricsDir := *localOutputDir
	if *metricsDir != "" {
		actualMetricsDir = *metricsDir
	}
	actualOutcomesDir := actualMetricsDir
	if *outcomesDir != "" {
		actualOutcomesDir = *outcomesDir
	} else if *csvDir != "" {
		actualOutcomesDir = *csvDir
	}

	logger.Info("Commencing CVE to OSV conversion run")
	if !*uploadToGCS && *localOutputDir != "" {
		if err := os.MkdirAll(*localOutputDir, 0755); err != nil {
			logger.Fatal("Failed to create local output directory", slog.Any("err", err))
		}
	}
	if *outputMetrics && actualMetricsDir != "" {
		if err := os.MkdirAll(actualMetricsDir, 0755); err != nil {
			logger.Fatal("Failed to create metrics directory", slog.Any("err", err))
		}
	}
	if *outputMetrics && actualOutcomesDir != "" {
		if err := os.MkdirAll(actualOutcomesDir, 0755); err != nil {
			logger.Fatal("Failed to create outcomes directory", slog.Any("err", err))
		}
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
		defer gcsHelper.CloseAndWait()
		logger.Info("GCS Upload Pool initialized", slog.String("bucket", *outputBucket))
	}

	repoTagsCache := git.NewRepoTagsCache()
	// Start the worker pool.
	for range *workers {
		wg.Add(1)
		go worker(&wg, jobs, gcsHelper, *localOutputDir, actualMetricsDir, cnaList, *rejectFailed, *outputMetrics, *gcsMetricsPrefix, repoTagsCache)
	}

	// Discover files and send them to the workers.
	logger.Info("Starting conversion of CVEs...")
	currentYear := time.Now().Year()
	startYearInt, _ := strconv.Atoi(*startYear)

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

	// Conduct analysis on the outcome of the converted files and output to a csv
	if *outputMetrics {
		conversion.ConductAnalysisAndUpload("cve5-conversion-outcomes-", "all", actualMetricsDir, actualOutcomesDir, gcsHelper, *gcsOutcomesPrefix)
	}

	timesBlocked := int64(0)
	if *uploadToGCS && gcsHelper != nil {
		timesBlocked = gcsHelper.GetTimesBlocked()
		gcsHelper.CloseAndWait()
	}

	logger.Info("Conversion Stats",
		slog.Uint64("total_processed", totalConversionsCount.Load()),
		slog.Uint64("successful_conversions", successfulConversionsCount.Load()),
		slog.Int64("times_gcs_upload_blocked", timesBlocked),
	)

	logger.Info("CVE5 Conversion run complete")
}

// worker is a function that processes CVE files from the jobs channel.
func worker(wg *sync.WaitGroup, jobs <-chan string, gcsHelper *gcs.Helper, outDir string, metricsDir string, cnas []string, rejectFailed bool, outputMetrics bool, gcsMetricsPrefix string, cache git.RepoTagsCache) {
	defer wg.Done()
	for path := range jobs {
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Info("Failed to read file", slog.String("path", path), slog.Any("err", err))
			continue
		}

		var cve models.CVE5
		if err := json.Unmarshal(data, &cve); err != nil {
			logger.Info("Failed to unmarshal JSON", slog.String("path", path), slog.Any("err", err))
			continue
		}

		if slices.Contains(cnas, cve.Metadata.AssignerShortName) || (cve.Metadata.State != "PUBLISHED" && cve.Metadata.State != "REJECTED") {
			continue
		}
		cveID := cve.Metadata.CVEID
		logger.Info("Processing "+string(cveID), slog.String("cve", string(cveID)))
		totalConversionsCount.Add(1)

		httpClient := http.DefaultClient

		sourceLink := ""
		baseDirCVEList := "cves/" // The base folder for the CVEListV5 repository.
		idx := strings.Index(path, baseDirCVEList)
		if idx != -1 {
			relPath := path[idx:]
			sourceLink = "https://github.com/CVEProject/cvelistV5/tree/main/" + relPath
		}

		if gcsHelper != nil {
			vuln, metrics := cve5.CVEToOSV(cve, sourceLink, cache, httpClient)
			if metrics.Outcome == models.Successful {
				successfulConversionsCount.Add(1)
			}
			if !metrics.Outcome.ShouldEmit(rejectFailed) {
				logger.Info("Rejecting failed OSV record", slog.String("cve", string(cveID)), slog.String("outcome", metrics.Outcome.String()))
			} else {
				if metrics.Outcome == models.Rejected {
					logger.Info("Queueing withdrawn OSV record for "+string(cveID), slog.String("cve", string(cveID)))
				} else {
					logger.Info("Queueing OSV record for "+string(cveID), slog.String("cve", string(cveID)))
				}
				if err := writer.UploadVulnIfChangedAsync(gcsHelper, *gcsPrefix, vuln.Vulnerability); err != nil {
					logger.Error("Failed to queue vulnerability upload", slog.String("cve", string(cveID)), slog.Any("err", err))
				}

				if outputMetrics {
					if err := writer.UploadMetricsToGCSAsync(gcsHelper, gcsMetricsPrefix, cveID, metrics); err != nil {
						logger.Error("Failed to queue metrics upload", slog.String("cve", string(cveID)), slog.Any("err", err))
					}
				}
			}

			// Always write metrics locally for outcomes CSV auditing
			if outputMetrics {
				metricsFile, err := writer.CreateMetricsFile(cveID, metricsDir)
				if err == nil {
					err = writer.WriteMetricsFile(metrics, metricsFile)
					if err != nil {
						logger.Error("Failed to write metrics file", slog.String("cve", string(cveID)), slog.Any("err", err))
					}
					metricsFile.Close()
				}
			}
		} else {
			osvFile, errCVE := writer.CreateOSVFile(cveID, outDir)
			if errCVE != nil {
				logger.Fatal("File failed to be created for CVE", slog.String("cve", string(cveID)))
			}

			var metricsFile *os.File
			var metricsSink io.Writer
			if outputMetrics {
				var errMetrics error
				metricsFile, errMetrics = writer.CreateMetricsFile(cveID, metricsDir)
				if errMetrics != nil {
					logger.Fatal("File failed to be created for CVE metrics", slog.String("cve", string(cveID)))
				}
				metricsSink = metricsFile
			}

			// Perform the conversion and export the results.
			metrics, err := cve5.ConvertAndExportCVEToOSV(cve, osvFile, metricsSink, sourceLink, cache, httpClient)
			if err != nil {
				logger.Warn("Failed to generate an OSV record", slog.String("cve", string(cveID)), slog.Any("err", err))
			} else {
				if metrics.Outcome == models.Successful {
					successfulConversionsCount.Add(1)
				}
				if !metrics.Outcome.ShouldEmit(rejectFailed) {
					logger.Info("Rejecting failed OSV record", slog.String("cve", string(cveID)), slog.String("outcome", metrics.Outcome.String()))
					osvFile.Close()
					os.Remove(osvFile.Name())
				} else {
					if metrics.Outcome == models.Rejected {
						logger.Info("Generated withdrawn OSV record for "+string(cveID), slog.String("cve", string(cveID)), slog.String("cna", cve.Metadata.AssignerShortName))
					} else {
						logger.Info("Generated OSV record for "+string(cveID), slog.String("cve", string(cveID)), slog.String("cna", cve.Metadata.AssignerShortName), slog.String("outcome", metrics.Outcome.String()))
					}
				}
			}

			if metricsFile != nil {
				metricsFile.Close()
			}
			osvFile.Close()
		}
	}
}
