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
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"time"

	"github.com/google/osv/vulnfeeds/cves"
	"github.com/google/osv/vulnfeeds/utility/logger"
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

var apiKey = flag.String("api_key", "", "API key for accessing NVD API 2.0")
var cvePath = flag.String("cvePath", CVEPathDefault, "Where to download CVEs to")

func main() {
	logger.InitGlobalLogger()

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
			logger.Warn("Bad response, retrying", slog.String("url", resp.Request.URL.String()), slog.String("status", resp.Status))
			return retry.RetryableError(fmt.Errorf("bad response for %q: %q", resp.Request.URL, resp.Status))
		default:
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				logger.Warn("Error reading response body, retrying", slog.String("url", resp.Request.URL.String()), slog.Any("err", err))
				return retry.RetryableError(fmt.Errorf("error reading response body for request for %q: %q", resp.Request.URL, resp.Status))
			}
			err = json.Unmarshal(body, &page)
			if err != nil {
				logger.Warn("Failed to decode NVD data", slog.Any("err", err))
				return fmt.Errorf("failed to decode NVD data from %q: %+w", resp.Request.URL, err)
			}

			return nil
		}
	}); err != nil {
		logger.Warn("Unable to retrieve", slog.String("url", APIURL.String()), slog.Any("err", err))
		return page, fmt.Errorf("unable to retrieve %q: %w", APIURL, err)
	}
	logger.Info("Retrieved", slog.Int("offset", page.StartIndex), slog.Int("total", page.TotalResults))

	return page, nil
}

// Download all of the CVE data using the 2.0 API
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2(apiKey string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, "nvdcve-2.0.json.new"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil { // There's an existing file, check if it matches server file
		logger.Fatal("Something went wrong when creating/opening file", slog.Any("err", err))
	}
	defer file.Close()
	var vulnerabilities []cves.Vulnerability
	var page *cves.CVEAPIJSON20Schema
	offset := 0
	prevTotal := 0
	for {
		page, err = downloadCVE2WithOffset(apiKey, offset)
		if err != nil {
			logger.Fatal("Failed to download", slog.Int("offset", offset), slog.Any("err", err))
		}
		if page.TotalResults < prevTotal {
			logger.Warn("TotalResults decreased", slog.Int("previous", prevTotal), slog.Int("current", page.TotalResults))
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
		logger.Fatal("Failed to write", slog.String("path", path.Join(cvePath, "nvdcve-2.0.json.new")), slog.Any("err", err))
	}
	file.Close()
	err = os.Rename(path.Join(cvePath, "nvdcve-2.0.json.new"), path.Join(cvePath, "nvdcve-2.0.json"))
	if err != nil {
		logger.Fatal("Failed to rename temporary file", slog.Any("err", err))
	}
}

func downloadCVE(version string, cvePath string) {
	file, err := os.OpenFile(path.Join(cvePath, fileNameBase+version+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil { // There's an existing file, check if it matches server file
		logger.Fatal("Something went wrong when creating/opening file", slog.String("version", version), slog.Any("err", err))
	}
	defer file.Close()

	res, err := http.Get(CVEURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		logger.Fatal("Failed to retrieve cve json", slog.Any("err", err), slog.String("version", version))
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		logger.Fatal("Failed to retrieve cve json", slog.Int("status_code", res.StatusCode), slog.String("version", version))
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		logger.Fatal("Failed to create gzip reader", slog.Any("err", err))
	}

	if _, err := io.CopyN(file, reader, 1024*1024*1024*10); err != nil && !errors.Is(err, io.EOF) { // 10GB limit
		logger.Fatal("Failed to write to file", slog.String("version", version), slog.Any("err", err))
	}
	logger.Info("Successfully downloaded CVE", slog.String("version", version))
}
