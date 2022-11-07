package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"

	"cloud.google.com/go/logging"
)

const (
	CVEURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	NVDAPIEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	PageSize       = 2000 // maximum page size with the 2.0 API is 2000
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	CVEPathDefault = "cve_jsons"
	projectId      = "oss-vdb"
)

var Logger utility.LoggerWrapper
var apiKey = flag.String("api_key", "", "API key for accessing NVD API 2.0")
var CVEPath = flag.String("cvePath", CVEPathDefault, "Where to download CVEs to")

func main() {
	client, err := logging.NewClient(context.Background(), projectId)
	if err != nil {
		log.Fatalf("Failed to create client: %v", err)
	}
	defer client.Close()
	Logger.GCloudLogger = client.Logger("download-cves")
	flag.Parse()
	if *apiKey != "" {
		downloadCVE2(*apiKey, *CVEPath)
	} else {
		currentYear := time.Now().Year()
		for i := startingYear; i <= currentYear; i++ {
			downloadCVE(strconv.Itoa(i), *CVEPath)
		}
		downloadCVE("modified", *CVEPath)
		downloadCVE("recent", *CVEPath)
	}
}

// Download one "page" of the CVE data using the 2.0 API
// Pages are offset based, this assumes the default (and maximum) page size of PageSize
// Maintaining the recommended 6 seconds betweens calls is left to the caller.
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2WithOffset(APIKey string, offset int) cves.NVDCVE2 {
	client := &http.Client{}
	APIURL, err := url.Parse(NVDAPIEndpoint)
	if err != nil {
		log.Fatalf("Failed to parse %s: %+v", NVDAPIEndpoint, err)
	}
	params := url.Values{}
	if offset > 0 {
		params.Add("startIndex", strconv.Itoa(offset))
	}
	APIURL.RawQuery = params.Encode()
	req, err := http.NewRequest("GET", fmt.Sprint(APIURL), nil)
	if APIKey != "" {
		req.Header.Add("apiKey", APIKey)
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
	var NVD2Data *cves.NVDCVE2
	err = json.Unmarshal(body, &NVD2Data)
	if err != nil {
		log.Fatalf("Failed to decode NVD data: %+v", err)
	}
	Logger.Infof("At offset %d of %d total results", *NVD2Data.StartIndex, *NVD2Data.TotalResults)
	return *NVD2Data
}

// Download all of the CVE data using the 2.0 API
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2(APIKey string, CVEPath string) {
	file, err := os.OpenFile(path.Join(CVEPath, "nvdcve-2.0.json.new"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		Logger.Fatalf("Something went wrong when creating/opening file: %+v", err)
	}
	var vulnerabilities []json.RawMessage
	page := cves.NVDCVE2{}
	offset := 0
	for {
		page = downloadCVE2WithOffset(APIKey, offset)
		vulnerabilities = append(vulnerabilities, page.Vulnerabilities...)
		offset += PageSize
		if offset > *page.TotalResults {
			break
		}
		time.Sleep(6)
	}
	// Make this look like one giant page of results from the API call
	page.Vulnerabilities = vulnerabilities
	*page.StartIndex = 0
	page.ResultsPerPage = page.TotalResults
	err = page.ToJSON(file)
	if err != nil {
		Logger.Fatalf("Failed to write %s: %+v", path.Join(CVEPath, "nvdcve-2.0.json.new"), err)
	}
	file.Close()
	os.Rename(path.Join(CVEPath, "nvdcve-2.0.json.new"), path.Join(CVEPath, "nvdcve-2.0.json"))
}

func downloadCVE(version string, CVEPath string) {
	file, err := os.OpenFile(path.Join(CVEPath, fileNameBase+version+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	defer file.Close()
	if err != nil { // There's an existing file, check if it matches server file
		Logger.Fatalf("Something went wrong when creating/opening file %s, %s", version, err)
	}

	res, err := http.Get(CVEURLBase + fileNameBase + version + ".json.gz")
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
