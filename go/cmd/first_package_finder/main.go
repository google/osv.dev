package main

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	debianReleaseVersionsURL = "https://salsa.debian.org/debian/distro-info-data/-/raw/main/debian.csv"
	debianSnapshotURL        = "https://snapshot.debian.org/archive/debian/%s/dists/"
	debianSourcesURLExt      = "%s/main/source/Sources.gz"
	firstReleaseLookahead    = 10
	packageKey               = "Package: "
	versionKey               = "Version: "
)

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
	firstSnapshotDate = time.Date(2005, 3, 12, 0, 0, 0, 0, time.UTC)
)

func convertDatetimeToStrDatetime(t time.Time) string {
	return t.UTC().Format("20060102T150405Z")
}

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

func retrieveCodenameToVersion() (map[string]*DebianVersionInfo, error) {
	resp, err := http.Get(debianReleaseVersionsURL)
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
		return nil, fmt.Errorf("empty csv")
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
		return nil, fmt.Errorf("missing required columns in csv")
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
			version = series
		}

		var releaseStr string
		if releaseIdx < len(row) {
			releaseStr = row[releaseIdx]
		}
		if releaseStr == "" && createdIdx < len(row) {
			releaseStr = row[createdIdx]
		}

		releaseDate, err := time.Parse("2006-01-02", releaseStr)
		if err != nil {
			log.Printf("Warning: failed to parse date %s for series %s", releaseStr, series)
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

func parseCreatedDatesAndSetTime(date time.Time) time.Time {
	result := date.Add(24 * time.Hour)
	if result.Before(firstSnapshotDate) {
		return firstSnapshotDate
	}
	return result
}

func loadSources(date time.Time, dist string) (map[string]string, error) {
	url := getDebianSourcesURL(date, dist)
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
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
		for i := 0; i <= firstReleaseLookahead; i++ {
			actualDate := date.Add(time.Duration(i) * 24 * time.Hour)
			log.Printf("attempting load of version %s at %s", series, actualDate)

			sources, err := loadSources(actualDate, series)
			if err == nil {
				info.Sources = sources
				log.Printf("loaded version %s at %s", series, actualDate)
				break
			}

			if !strings.Contains(err.Error(), "HTTP 404") {
				log.Printf("Error loading sources for %s at %s: %v", series, actualDate, err)
			}

			if actualDate.After(time.Now()) {
				break
			}
		}
	}

	return codenameToVersion, nil
}

func main() {
	var outputDir string
	flag.StringVar(&outputDir, "o", "first_package_output", "Output folder")
	flag.StringVar(&outputDir, "output-dir", "first_package_output", "Output folder")
	flag.Parse()

	log.SetFlags(log.LstdFlags | log.Lshortfile)

	codenameToVersion, err := loadFirstPackages()
	if err != nil {
		log.Fatalf("Failed to load first packages: %v", err)
	}

	log.Println("first_package loaded, begin writing out data")

	if err := os.MkdirAll(outputDir, 0755); err != nil {
		log.Fatalf("Failed to create output directory: %v", err)
	}

	for _, info := range codenameToVersion {
		if info.Sources == nil {
			continue
		}

		outPath := filepath.Join(outputDir, info.Version+".json")
		b, err := json.Marshal(info.Sources)
		if err != nil {
			log.Printf("Failed to marshal sources for %s: %v", info.Version, err)
			continue
		}

		if err := os.WriteFile(outPath, b, 0644); err != nil {
			log.Printf("Failed to write to %s: %v", outPath, err)
		}
	}
}
