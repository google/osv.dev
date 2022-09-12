package main

import (
	"compress/gzip"
	"context"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"cloud.google.com/go/logging"
	"github.com/google/osv/vulnfeeds/utility"
)

const (
	cveURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	cvePathDefault = "cve_jsons"
	projectId      = "oss-vdb"
)

var LOGGER utility.LoggerWrapper

func main() {
	client, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	LOGGER.Logger = client.Logger("combine-to-osv")

	cvePath := flag.String("cvePath", cvePathDefault, "Where to download CVEs to")
	flag.Parse()
	currentYear := time.Now().Year()
	for i := startingYear; i <= currentYear; i++ {
		downloadCVE(strconv.Itoa(i), *cvePath)
	}
	downloadCVE("modified", *cvePath)
	downloadCVE("recent", *cvePath)
}

func downloadCVE(version string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, fileNameBase+version+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		LOGGER.FatalLogf("Something's went wrong when creating/opening file %s, %s", version, err)
	}

	res, err := http.Get(cveURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		LOGGER.FatalLogf("Failed to retrieve cve json with: %d, for version: %s", err, version)
	}

	if res.StatusCode != 200 {
		LOGGER.FatalLogf("Failed to retrieve cve json with: %d, for version: %s", res.StatusCode, version)
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		LOGGER.FatalLogf("Failed to create gzip reader: %s", err)
	}

	if _, err := io.Copy(file, reader); err != nil {
		LOGGER.FatalLogf("Failed to write to file %s: %s", version, err)
	}
	LOGGER.InfoLogf(
		"Successfully downloaded CVE %s\n", version)
}
