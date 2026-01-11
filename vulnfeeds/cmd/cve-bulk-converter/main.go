// Package main converts CVEs to OSV format in bulk.
package main

import (
	_ "embed"
	"encoding/json"
	"flag"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/osv/vulnfeeds/cvelist2osv"
	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility/logger"
)

var (
	repoDir        = flag.String("cve5-repo", "cvelistV5", "CVEListV5 directory path")
	localOutputDir = flag.String("out-dir", "cvelist2osv", "Path to output results.")
	startYear      = flag.String("start-year", "2022", "The first in scope year to process.")
	workers        = flag.Int("workers", 30, "The number of concurrent workers to use for processing CVEs.")
	cnaAllowList   = flag.String("cnas-allowlist", "", "A comma-separated list of CNAs to process. If not provided, defaults to cna_allowlist.txt.")
)

//go:embed cna_allowlist.txt
var cnaAllowlistData []byte

func main() {
	flag.Parse()
	logger.InitGlobalLogger()

	logger.Info("Commencing Linux CVE to OSV conversion run")
	if err := os.MkdirAll(*localOutputDir, 0755); err != nil {
		logger.Fatal("Failed to create local output directory", slog.Any("err", err))
	}

	jobs := make(chan string)
	var wg sync.WaitGroup
	var cnaList []string
	if *cnaAllowList != "" {
		cnaList = strings.Split(*cnaAllowList, ",")
	} else {
		for _, cna := range strings.Split(string(cnaAllowlistData), "\n") {
			cna = strings.TrimSpace(cna)
			if cna != "" {
				cnaList = append(cnaList, cna)
			}
		}
	}

	// Start the worker pool.
	for range *workers {
		wg.Add(1)
		go worker(&wg, jobs, *localOutputDir, cnaList)
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
	logger.Info("Conversion run complete")
}

// worker is a function that processes CVE files from the jobs channel.
func worker(wg *sync.WaitGroup, jobs <-chan string, outDir string, cnas []string) {
	defer wg.Done()
	for path := range jobs {
		data, err := os.ReadFile(path)
		if err != nil {
			logger.Info("Failed to read file", slog.String("path", path), slog.Any("err", err))
			continue
		}

		var cve cves.CVE5
		if err := json.Unmarshal(data, &cve); err != nil {
			logger.Info("Failed to unmarshal JSON", slog.String("path", path), slog.Any("err", err))
			continue
		}

		if !slices.Contains(cnas, cve.Metadata.AssignerShortName) || cve.Metadata.State != "PUBLISHED" {
			continue
		}
		cveID := cve.Metadata.CVEID
		logger.Info("Processing "+string(cveID), slog.String("cve", string(cveID)))

		osvFile, errCVE := cvelist2osv.CreateOSVFile(cveID, outDir)
		metricsFile, errMetrics := cvelist2osv.CreateMetricsFile(cveID, outDir)
		if errCVE != nil || errMetrics != nil {
			logger.Fatal("File failed to be created for CVE", slog.String("cve", string(cveID)))
		}

		sourceLink := ""
		baseDirCVEList := "cves/" // The base folder for the CVEListV5 repository.
		idx := strings.Index(path, baseDirCVEList)
		if idx != -1 {
			relPath := path[idx:]
			sourceLink = "https://github.com/CVEProject/cvelistV5/tree/main/" + relPath
		}

		// Perform the conversion and export the results.
		if err = cvelist2osv.ConvertAndExportCVEToOSV(cve, osvFile, metricsFile, sourceLink); err != nil {
			logger.Warn("Failed to generate an OSV record", slog.String("cve", string(cveID)), slog.Any("err", err))
		} else {
			logger.Info("Generated OSV record for "+string(cveID), slog.String("cve", string(cveID)), slog.String("cna", cve.Metadata.AssignerShortName))
		}

		metricsFile.Close()
		osvFile.Close()
	}
}
