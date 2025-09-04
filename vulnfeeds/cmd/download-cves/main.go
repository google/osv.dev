// download-cves downloads CVEs from NVD.
package main

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility"
	"github.com/sethvargo/go-retry"
)

const (
	CVEURLBase     = "https://nvd.nist.gov/feeds/json/cve/1.1/"
	NVDAPIEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	PageSize       = 2000 // maximum page size with the 2.0 API is 2000
	fileNameBase   = "nvdcve-1.1-"
	startingYear   = 2002
	CVEPathDefault = "cve_jsons"
)

var Logger utility.LoggerWrapper
var apiKey = flag.String("api_key", "", "API key for accessing NVD API 2.0")
var cvePath = flag.String("cvePath", CVEPathDefault, "Where to download CVEs to")

func main() {
	var logCleanup func()
	Logger, logCleanup = utility.CreateLoggerWrapper("download-cves")
	defer logCleanup()

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

// Download one "page" of the CVE data using the 2.0 API.
// Pages are offset based, this assumes the default (and maximum) page size of PageSize
// Maintaining the recommended 6 seconds betweens calls is left to the caller.
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2WithOffset(apiKey string, offset int) (page *cves.CVEAPIJSON20Schema, err error) {
	client := &http.Client{}
	APIURL, err := url.Parse(NVDAPIEndpoint)
	if err != nil {
		return page, fmt.Errorf("failed to parse %s: %+w", NVDAPIEndpoint, err)
	}
	params := url.Values{}
	if offset > 0 {
		params.Add("startIndex", strconv.Itoa(offset))
	}
	APIURL.RawQuery = params.Encode()
	req, err := http.NewRequest(http.MethodGet, fmt.Sprint(APIURL), nil)
	if err != nil {
		return page, fmt.Errorf("request creation for %q failed: %+w", APIURL, err)
	}
	if apiKey != "" {
		// apiKey is the correct header type that NVD expects
		// https://nvd.nist.gov/developers/start-here
		//nolint:canonicalheader
		req.Header.Add("apiKey", apiKey)
	}
	backoff := retry.NewExponential(6 * time.Second)
	if err := retry.Do(context.Background(), retry.WithMaxRetries(3, backoff), func(ctx context.Context) error {
		req := req.WithContext(ctx)
		resp, err := client.Do(req)
		if err != nil {
			return nil
		}
		defer resp.Body.Close()

		switch resp.StatusCode / 100 {
		case 4:
			return fmt.Errorf("bad response for %q: %q", resp.Request.URL, resp.Status)
		case 5:
			Logger.Warnf("Bad response for %q: %q, retrying", resp.Request.URL, resp.Status)
			return retry.RetryableError(fmt.Errorf("bad response for %q: %q", resp.Request.URL, resp.Status))
		default:
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				Logger.Warnf("Error reading response body for request for %q: %+v, retrying", resp.Request.URL, err)
				return retry.RetryableError(fmt.Errorf("error reading response body for request for %q: %q", resp.Request.URL, resp.Status))
			}
			err = json.Unmarshal(body, &page)
			if err != nil {
				Logger.Warnf("Failed to decode NVD data: %q", err)
				return fmt.Errorf("failed to decode NVD data from %q: %+w", resp.Request.URL, err)
			}

			return nil
		}
	}); err != nil {
		Logger.Warnf("Unable to retrieve %q: %v", APIURL, err)
		return page, fmt.Errorf("unable to retrieve %q: %w", APIURL, err)
	}
	Logger.Infof("Retrieved offset %d of %d total results", page.StartIndex, page.TotalResults)

	return page, nil
}

// Download all of the CVE data using the 2.0 API
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2(apiKey string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, "nvdcve-2.0.json.new"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil { // There's an existing file, check if it matches server file
		Logger.Fatalf("Something went wrong when creating/opening file: %+v", err)
	}
	defer file.Close()
	var vulnerabilities []cves.Vulnerability
	var page *cves.CVEAPIJSON20Schema
	offset := 0
	prevTotal := 0
	for {
		page, err = downloadCVE2WithOffset(apiKey, offset)
		if err != nil {
			Logger.Fatalf("Failed to download at offset %d: %+v", offset, err)
		}
		if page.TotalResults < prevTotal {
			Logger.Warnf("TotalResults decreased from %d to %d", prevTotal, page.TotalResults)
		}
		prevTotal = page.TotalResults
		vulnerabilities = append(vulnerabilities, page.Vulnerabilities...)
		offset += PageSize
		if offset > page.TotalResults {
			break
		}
		time.Sleep(6 * time.Second)
	}
	// Make this look like one giant page of results from the API call
	page.Vulnerabilities = vulnerabilities
	page.StartIndex = 0
	page.ResultsPerPage = page.TotalResults
	err = page.ToJSON(file)
	if err != nil {
		Logger.Fatalf("Failed to write %s: %+v", path.Join(cvePath, "nvdcve-2.0.json.new"), err)
	}
	file.Close()
	err = os.Rename(path.Join(cvePath, "nvdcve-2.0.json.new"), path.Join(cvePath, "nvdcve-2.0.json"))
	if err != nil {
		Logger.Fatalf("Failed to rename temporary file: %+v", err)
	}
}

func downloadCVE(version string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, fileNameBase+version+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil { // There's an existing file, check if it matches server file
		Logger.Fatalf("Something went wrong when creating/opening file %s, %s", version, err)
	}
	defer file.Close()

	res, err := http.Get(CVEURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		Logger.Fatalf("Failed to retrieve cve json with: %d, for version: %s", err, version)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		Logger.Fatalf("Failed to retrieve cve json with: %d, for version: %s", res.StatusCode, version)
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		Logger.Fatalf("Failed to create gzip reader: %s", err)
	}

	if _, err := io.CopyN(file, reader, 1024*1024*1024*10); err != nil && !errors.Is(err, io.EOF) { // 10GB limit
		Logger.Fatalf("Failed to write to file %s: %s", version, err)
	}
	Logger.Infof(
		"Successfully downloaded CVE %s\n", version)
}
