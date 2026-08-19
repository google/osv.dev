// Package main converts a single CVE5 to OSV format
package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"os"

	"github.com/google/osv.dev/vulnfeeds/conversion/cve5"
	"github.com/google/osv.dev/vulnfeeds/conversion/writer"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
)

var (
	outDir     = flag.String("out-dir", "", "Path to output results.")
	metricsDir = flag.String("metrics-dir", "", "Path to output metrics JSON file. Defaults to out-dir.")
)

func main() {
	flag.Parse()
	jsonPath := flag.Arg(0)

	logger.InitGlobalLogger()
	defer logger.Close()

	// Read the input CVE JSON file.
	data, err := os.ReadFile(jsonPath)
	if err != nil {
		logger.Fatal("Failed to open file", slog.Any("err", err))
	}

	var cve models.CVE5
	if err = json.Unmarshal(data, &cve); err != nil {
		logger.Fatal("Failed to parse CVEList CVE JSON", slog.Any("err", err))
	}

	outDir := *outDir
	if outDir == "" {
		outDir = cve.Metadata.AssignerShortName
	}
	metricsDir := *metricsDir
	if metricsDir == "" {
		metricsDir = outDir
	}
	cveID := cve.Metadata.CVEID
	err = os.MkdirAll(outDir, 0755)
	if err != nil {
		logger.Warn("Failed to create dir", slog.Any("err", err))
	}
	if metricsDir != outDir {
		err = os.MkdirAll(metricsDir, 0755)
		if err != nil {
			logger.Warn("Failed to create metrics dir", slog.Any("err", err))
		}
	}
	// create the files

	osvFile, errCVE := writer.CreateOSVFile(cveID, outDir)
	metricsFile, errMetrics := writer.CreateMetricsFile(cveID, metricsDir)
	if errCVE != nil || errMetrics != nil {
		logger.Fatal("File failed to be created for CVE", slog.String("cve", string(cveID)))
	}

	// Perform the conversion and export the results.
	if metrics, err := cve5.ConvertAndExportCVEToOSV(cve, osvFile, metricsFile, ""); err != nil {
		logger.Warn("Failed to generate an OSV record", slog.String("cve", string(cveID)), slog.Any("err", err))
	} else {
		logger.Info("Generated OSV record for "+string(cveID), slog.String("cve", string(cveID)), slog.String("cna", cve.Metadata.AssignerShortName), slog.String("outcome", metrics.Outcome.String()))
	}

	metricsFile.Close()
	osvFile.Close()
}
