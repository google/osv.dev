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

	"github.com/google/osv/vulnfeeds/utility"

	"cloud.google.com/go/logging"
)

const (
	cveURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	cvePathDefault = "cve_jsons"
	projectId      = "oss-vdb"
)

var Logger utility.LoggerWrapper

func main() {
	client, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	Logger.GCloudLogger = client.Logger("combine-to-osv")

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
		Logger.Fatalf("Something's went wrong when creating/opening file %s, %s", version, err)
	}

	res, err := http.Get(cveURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		Logger.Fatalf("Failed to retrieve cve json with: %d, for version: %s", err, version)
	}

	if res.StatusCode != 200 {
		Logger.Fatalf("Failed to retrieve cve json with: %d, for version: %s", res.StatusCode, version)
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		Logger.Fatalf("Failed to create gzip reader: %s", err)
	}

	if _, err := io.Copy(file, reader); err != nil {
		Logger.Fatalf("Failed to write to file %s: %s", version, err)
	}
	Logger.Infof(
		"Successfully downloaded CVE %s\n", version)
}
