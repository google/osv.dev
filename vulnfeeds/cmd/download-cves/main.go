package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"

	"cloud.google.com/go/logging"
)

const (
	cveURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	nvdAPI         = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	cvePathDefault = "cve_jsons"
	projectId      = "oss-vdb"
)

var Logger utility.LoggerWrapper
var apiKey = flag.String("api_key", "", "API key for accessing NVD API 2.0")
var cvePath = flag.String("cvePath", cvePathDefault, "Where to download CVEs to")

func main() {
	client, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	Logger.GCloudLogger = client.Logger("download-cves")
	flag.Parse()
	if *apiKey != "" {
		downloadCVE2(*apiKey, *cvePath)
	} else {
		currentYear := time.Now().Year()
		for i := startingYear; i <= currentYear; i++ {
			downloadCVE(strconv.Itoa(i), *cvePath)
		}
		downloadCVE("modified", *cvePath)
		downloadCVE("recent", *cvePath)
	}
}

// Download all of the CVE data using the 2.0 API
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2(apiKey string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, "nvdcve-2.0.json.new"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		Logger.Fatalf("Something went wrong when creating/opening file: %+v", err)
	}
	client := &http.Client{}
	req, err := http.NewRequest("GET", nvdAPI, nil)
	if apiKey != "" {
		req.Header.Add("apiKey", apiKey)
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Fatalf("Request failed: %+v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Error reading response body: %+v", err)
	}
	var NVD2Data cves.NVDCVE2
	err = json.Unmarshal(body, &NVD2Data)
	if err != nil {
		log.Fatalf("Failed to decode NVD data: %+v", err)
	}
	Logger.Infof("%d results to download", NVD2Data.TotalResults)
	// TODO: figure out how to paginate
	file.Write(body)
	file.Close()
	os.Rename(path.Join(cvePath, "nvdcve-2.0.json.new"), path.Join(cvePath, "nvdcve-2.0.json"))
}

func downloadCVE(version string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, fileNameBase+version+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		Logger.Fatalf("Something went wrong when creating/opening file %s, %s", version, err)
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
