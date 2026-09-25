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

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/vulnfeeds/gcs-tools"
	"github.com/google/osv.dev/vulnfeeds/models"
	"github.com/google/osv.dev/vulnfeeds/utility/logger"
	"github.com/sethvargo/go-retry"
	"golang.org/x/sync/errgroup"
)

const (
	CVEURLBase     = "https://nvd.nist.gov/feeds/json/cve/2.0/"
	NVDAPIEndpoint = "https://services.nvd.nist.gov/rest/json/cves/2.0"
	PageSize       = 2000 // maximum page size with the 2.0 API is 2000
	fileNameBase   = "nvdcve-2.0-"
	startingYear   = 2002
	CVEPathDefault = "cve_jsons"
	GCSDir         = "nvd"
	maxFileSize    = 1024 * 1024 * 1024 * 10 // 10GB
)

// Note that we were originally downloading NVD data from data dumps - which were deprecated,
// so we began using the API. The data dumps are now undeprecated and are a more reliable
// source of data. API code here will remain just in case.

// var apiKey = flag.String("api_key", "", "API key for accessing NVD API 2.0")
var cvePath = flag.String("cve-path", CVEPathDefault, "Where to download CVEs to")
var gcsBucket = flag.String("gcs-bucket", "", "GCS bucket to upload to. If empty, downloads locally.")

func main() {
	logger.InitGlobalLogger()
	defer logger.Close()

	flag.Parse()

	ctx := context.Background()
	var bkt *storage.BucketHandle
	if *gcsBucket != "" {
		client, err := storage.NewClient(ctx)
		if err != nil {
			logger.Fatal("Failed to create storage client", slog.Any("err", err))
		}
		bkt = client.Bucket(*gcsBucket)
	}

	// if *apiKey != "" {
	// 	downloadCVE2FromAPI(*apiKey, *cvePath)
	// } else {
	g, ctx := errgroup.WithContext(ctx)
	// Limit concurrency to avoid overwhelming the network or NVD server
	g.SetLimit(10)

	currentYear := time.Now().Year()
	for i := startingYear; i <= currentYear; i++ {
		version := strconv.Itoa(i)
		g.Go(func() error {
			if bkt != nil {
				return downloadCVEFromDataDumpsToGCS(ctx, bkt, version)
			}

			return downloadCVEFromDataDumps(version, *cvePath)
		})
	}

	g.Go(func() error {
		if bkt != nil {
			return downloadCVEFromDataDumpsToGCS(ctx, bkt, "modified")
		}

		return downloadCVEFromDataDumps("modified", *cvePath)
	})

	g.Go(func() error {
		if bkt != nil {
			return downloadCVEFromDataDumpsToGCS(ctx, bkt, "recent")
		}

		return downloadCVEFromDataDumps("recent", *cvePath)
	})

	if err := g.Wait(); err != nil {
		logger.Error("Failed to complete all downloads", slog.Any("err", err))
	}
}

// Download one "page" of the CVE data using the 2.0 API.
// Pages are offset based, this assumes the default (and maximum) page size of PageSize
// Maintaining the recommended 6 seconds betweens calls is left to the caller.
// See https://nvd.nist.gov/developers/vulnerabilities
func downloadCVE2FromAPIWithOffset(apiKey string, offset int) (page *models.CVEAPIJSON20Schema, err error) { //nolint:unused
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
func downloadCVE2FromAPI(apiKey string, cvePath string) { //nolint:unused
	file, err := os.OpenFile(path.Join(cvePath, "nvdcve-2.0.json.new"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil { // There's an existing file, check if it matches server file
		logger.Fatal("Something went wrong when creating/opening file", slog.Any("err", err))
	}
	defer file.Close()
	var vulnerabilities []models.Vulnerability
	var page *models.CVEAPIJSON20Schema
	offset := 0
	prevTotal := 0
	for {
		page, err = downloadCVE2FromAPIWithOffset(apiKey, offset)
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

func downloadAndProcess(version string, writeFunc func(io.Reader) error) error {
	res, err := http.Get(CVEURLBase + fileNameBase + version + ".json.gz")
	if err != nil {
		return fmt.Errorf("failed to retrieve cve json: %w", err)
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to retrieve cve json: status code %d", res.StatusCode)
	}

	reader, err := gzip.NewReader(res.Body)
	if err != nil {
		return fmt.Errorf("failed to create gzip reader: %w", err)
	}
	defer reader.Close()

	return writeFunc(reader)
}

func downloadCVEFromDataDumps(version string, cvePath string) error {
	file, err := os.OpenFile(path.Join(cvePath, fileNameBase+version+".json"), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
	if err != nil { // There's an existing file, check if it matches server file
		return fmt.Errorf("something went wrong when creating/opening file: %w", err)
	}
	defer file.Close()

	err = downloadAndProcess(version, func(r io.Reader) error {
		n, err := io.Copy(file, io.LimitReader(r, maxFileSize))
		if err != nil {
			return err
		}
		if n >= maxFileSize {
			var buf [1]byte
			if _, err := r.Read(buf[:]); err == nil {
				return fmt.Errorf("file exceeded limit of %d bytes", maxFileSize)
			} else if !errors.Is(err, io.EOF) {
				return fmt.Errorf("error checking for remaining data: %w", err)
			}
		}

		return nil
	})
	if err != nil {
		return err
	}
	logger.Info("Successfully downloaded CVE "+version, slog.String("version", version))

	return nil
}

func downloadCVEFromDataDumpsToGCS(ctx context.Context, bkt *storage.BucketHandle, version string) error {
	objectName := GCSDir + "/" + fileNameBase + version + ".json"

	err := downloadAndProcess(version, func(r io.Reader) error {
		if err := gcs.UploadToGCS(ctx, bkt, objectName, io.LimitReader(r, maxFileSize), "application/json", nil); err != nil {
			return err
		}
		// Check if we hit the limit
		var buf [1]byte
		if _, err := r.Read(buf[:]); err == nil {
			return fmt.Errorf("file exceeded limit of %d bytes", maxFileSize)
		} else if !errors.Is(err, io.EOF) {
			return fmt.Errorf("error checking for remaining data: %w", err)
		}

		return nil
	})
	if err != nil {
		return err
	}
	logger.Info("Successfully streamed CVE to GCS "+version, slog.String("version", version))

	return nil
}
