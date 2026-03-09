// Package main finds the first package versions for Debian releases.
package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/logger"
)

const (
	debianReleaseVersionsURL = "https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian.csv"
	debianSnapshotURL        = "https://snapshot.debian.org/archive/debian/%s/dists/"
	debianSourcesURLExt      = "%s/main/source/Sources.gz" // `.gz` format always exist for all snapshots
	firstReleaseLookahead    = 10                          // Number of days to search (day by day) if the initial date returns 404
	packageKey               = "Package: "                 // Prefixes used in the Sources file
	versionKey               = "Version: "
)

// List of ignored versions, mostly too early to be in snapshots
var (
	ignoredDebianVersions = map[string]bool{
		"experimental": true,
		"buzz":         true,
		"rex":          true,
		"bo":           true,
		"hamm":         true,
		"slink":        true,
		"potato":       true,
	}
	firstSnapshotDate = time.Date(2005, 3, 12, 0, 0, 0, 0, time.UTC) // First snapshot date for Debian
)

// HTTPError represents an error from an HTTP request, including the status code.
type HTTPError struct {
	StatusCode int
	URL        string
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("HTTP %d for URL: %s", e.StatusCode, e.URL)
}

// convertDatetimeToStrDatetime converts datetime object to debian snapshot url string
func convertDatetimeToStrDatetime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

// getDebianSourcesURL creates an url for snapshot.debian.org
func getDebianSourcesURL(date time.Time, version string) string {
	formattedDate := convertDatetimeToStrDatetime(date)
	return fmt.Sprintf(debianSnapshotURL, formattedDate) + fmt.Sprintf(debianSourcesURLExt, version)
}

type DebianVersionInfo struct {
	Series  string
	Version string
	Release time.Time
	Sources map[string]string
}

// retrieveCodenameToVersion returns the codename to version mapping
func retrieveCodenameToVersion() (map[string]*DebianVersionInfo, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(debianReleaseVersionsURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	reader := csv.NewReader(resp.Body)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return nil, err
	}

	if len(records) == 0 {
		return nil, errors.New("empty csv")
	}

	headers := records[0]
	seriesIdx, versionIdx, releaseIdx, createdIdx := -1, -1, -1, -1
	for i, h := range headers {
		switch h {
		case "series":
			seriesIdx = i
		case "version":
			versionIdx = i
		case "release":
			releaseIdx = i
		case "created":
			createdIdx = i
		}
	}

	if seriesIdx == -1 || versionIdx == -1 || releaseIdx == -1 || createdIdx == -1 {
		return nil, errors.New("missing required columns in csv")
	}

	result := make(map[string]*DebianVersionInfo)
	for _, row := range records[1:] {
		var series string
		if seriesIdx < len(row) {
			series = row[seriesIdx]
		}
		var version string
		if versionIdx < len(row) {
			version = row[versionIdx]
		}
		if version == "" {
			// series appears to be codename but with no caps
			version = series
		}

		var releaseStr string
		if releaseIdx < len(row) {
			releaseStr = row[releaseIdx]
		}
		if releaseStr == "" && createdIdx < len(row) {
			// Set release to created if not yet released
			releaseStr = row[createdIdx]
		}

		releaseDate, err := time.Parse("2006-01-02", releaseStr)
		if err != nil {
			slog.Warn("Failed to parse date", "date", releaseStr, "series", series)
			continue
		}

		result[series] = &DebianVersionInfo{
			Series:  series,
			Version: version,
			Release: releaseDate,
		}
	}

	return result, nil
}

// parseCreatedDatesAndSetTime parses created date in debian version csv to datetime plus one day
func parseCreatedDatesAndSetTime(date time.Time) time.Time {
	result := date.Add(24 * time.Hour)
	if result.Before(firstSnapshotDate) {
		// Set minimum date to first debian snapshot
		return firstSnapshotDate
	}

	return result
}

// loadSources loads the sources file and store in a dictionary of {name: version}
func loadSources(date time.Time, dist string) (map[string]string, error) {
	url := getDebianSourcesURL(date, dist)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{StatusCode: resp.StatusCode, URL: url}
	}

	gzReader, err := gzip.NewReader(resp.Body)
	if err != nil {
		return nil, err
	}
	defer gzReader.Close()

	scanner := bufio.NewScanner(gzReader)
	packageVersionDict := make(map[string]string)
	var currentPackage string

	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, packageKey) {
			currentPackage = line[len(packageKey):]
			continue
		}
		if strings.HasPrefix(line, versionKey) {
			packageVersionDict[currentPackage] = line[len(versionKey):]
			continue
		}
	}

	return packageVersionDict, scanner.Err()
}

// loadFirstPackages loads the dataframe containing the first version of packages per distro
func loadFirstPackages() (map[string]*DebianVersionInfo, error) {
	codenameToVersion, err := retrieveCodenameToVersion()
	if err != nil {
		return nil, err
	}

	for series, info := range codenameToVersion {
		if ignoredDebianVersions[series] {
			continue
		}

		date := parseCreatedDatesAndSetTime(info.Release)
		// retry for n days into the future if the first request doesn't work
		for i := 0; i <= firstReleaseLookahead; i++ {
			actualDate := date.Add(time.Duration(i) * 24 * time.Hour)
			slog.Info("Attempting load of version", "series", series, "date", actualDate)

			sources, err := loadSources(actualDate, series)
			if err == nil {
				info.Sources = sources
				slog.Info("Loaded version", "series", series, "date", actualDate)

				break
			}

			var httpErr *HTTPError
			// Expect 404 errors for releases before snapshot exists
			if !errors.As(err, &httpErr) || httpErr.StatusCode != http.StatusNotFound {
				slog.Error("Error loading sources", "series", series, "date", actualDate, "err", err)
			}

			if actualDate.After(time.Now()) {
				// No need to keep trying future dates
				break
			}
		}
	}

	return codenameToVersion, nil
}

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()
	var outputDir string
	var uploadToGCS bool
	var outputBucket string

	flag.StringVar(&outputDir, "o", "first_package_output", "Output folder")
	flag.StringVar(&outputDir, "output-dir", "first_package_output", "Output folder")
	flag.BoolVar(&uploadToGCS, "upload-to-gcs", false, "Upload to GCS")
	flag.StringVar(&outputBucket, "output-bucket", "debian-osv", "Output bucket")
	flag.Parse()

	flag.Parse()

	codenameToVersion, err := loadFirstPackages()
	if err != nil {
		logger.Error("Failed to load first packages", "err", err)
		logger.Close() //nolint:errcheck
		os.Exit(1)
	}

	logger.Info("first_package loaded, begin writing out data")

	var outBkt *storage.BucketHandle
	var ctx context.Context
	if uploadToGCS {
		ctx = context.Background()
		storageClient, err := storage.NewClient(ctx)
		if err != nil {
			logger.Error("Failed to create storage client", "err", err)
			os.Exit(1)
		}
		outBkt = storageClient.Bucket(outputBucket)
	} else {
		if err := os.MkdirAll(outputDir, 0755); err != nil {
			logger.Error("Failed to create output directory", "err", err)
			os.Exit(1)
		}
	}

	for _, info := range codenameToVersion {
		if info.Sources == nil {
			continue
		}

		b, err := json.Marshal(info.Sources)
		if err != nil {
			logger.Error("Failed to marshal sources", "version", info.Version, "err", err)
			continue
		}

		if uploadToGCS {
			objName := filepath.Join(outputDir, info.Version+".json")
			obj := outBkt.Object(objName)
			wc := obj.NewWriter(ctx)
			wc.ContentType = "application/json"
			if _, err := wc.Write(b); err != nil {
				logger.Error("Failed to write to GCS object", "objName", objName, "err", err)
				wc.Close()

				continue
			}
			if err := wc.Close(); err != nil {
				logger.Error("Failed to close GCS writer", "objName", objName, "err", err)
			}
			logger.Info("Uploaded to GCS", "objName", objName)
		} else {
			outPath := filepath.Join(outputDir, info.Version+".json")
			//nolint:gosec // 0644 is fine for public vulnerability data
			if err := os.WriteFile(outPath, b, 0644); err != nil {
				logger.Error("Failed to write to file", "outPath", outPath, "err", err)
			}
		}
	}
	logger.Info("Finished")
}
