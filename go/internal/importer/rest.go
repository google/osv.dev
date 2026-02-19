package importer

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/tidwall/gjson"
)

type restSourceRecord struct {
	cl      *http.Client
	urlBase string
	urlPath string
}

var _ SourceRecord = restSourceRecord{}

func (r restSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
	u, err := url.JoinPath(r.urlBase, r.urlPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	resp, err := r.cl.Do(req)
	if err != nil {
		return nil, err
	}

	return resp.Body, nil
}

func handleImportREST(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeREST || sourceRepo.REST == nil {
		return errors.New("invalid SourceRepository for REST import")
	}
	logger.InfoContext(ctx, "Importing REST source repository",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)
	hasUpdateTime := false
	var lastUpdated time.Time
	if !sourceRepo.REST.IgnoreLastImportTime && sourceRepo.REST.LastUpdated != nil {
		lastUpdated = *sourceRepo.REST.LastUpdated
		hasUpdateTime = true
	}
	timeOfRun := time.Now()
	var lastModTime time.Time
	if hasUpdateTime {
		var err error
		lastModTime, err = checkHEAD(ctx, config, sourceRepo)
		if err != nil {
			return err
		}
		if !lastModTime.IsZero() && lastModTime.Before(lastUpdated) {
			logger.InfoContext(ctx, "No changes since last update.",
				slog.String("source", sourceRepo.Name),
				slog.String("url", sourceRepo.REST.URL))

			return nil
		}
	}

	req, err := http.NewRequest(http.MethodGet, sourceRepo.REST.URL, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	resp, err := config.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.ErrorContext(ctx, "Failed to fetch REST API", slog.String("source", sourceRepo.Name), slog.Int("status_code", resp.StatusCode), slog.String("url", sourceRepo.REST.URL))

		return fmt.Errorf("failed to fetch REST API: %d for %s", resp.StatusCode, sourceRepo.REST.URL)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.ErrorContext(ctx, "Failed to read REST API response", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL), slog.Any("error", err))

		return err
	}
	result := gjson.ParseBytes(data)
	if !result.IsArray() {
		logger.ErrorContext(ctx, "REST API response is not an array", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))

		return fmt.Errorf("REST API response is not an array for %s", sourceRepo.REST.URL)
	}
	maxModified := time.Time{}
	result.ForEach(func(_, vuln gjson.Result) bool {
		id := vuln.Get("id")
		if !id.Exists() {
			logger.ErrorContext(ctx, "Vulnerability missing id", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))

			return true
		}
		modified := vuln.Get("modified")
		if !modified.Exists() {
			logger.ErrorContext(ctx, "Vulnerability missing modified", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL), slog.String("id", id.String()))

			return true
		}
		mod, err := time.Parse(time.RFC3339, modified.String())
		if err != nil {
			logger.ErrorContext(ctx, "Failed to parse modified", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL), slog.String("id", id.String()), slog.Any("error", err))

			return true
		}
		if mod.After(maxModified) {
			maxModified = mod
		}
		if hasUpdateTime && mod.Before(lastUpdated) {
			return true
		}
		if shouldIgnore(id.String(), sourceRepo.IDPrefixes, compiledIgnorePatterns) {
			return true
		}
		path := id.String() + sourceRepo.Extension
		ch <- WorkItem{
			Context: ctx,
			SourceRecord: restSourceRecord{
				cl:      config.HTTPClient,
				urlBase: sourceRepo.Link,
				urlPath: path,
			},
			SourceRepository: sourceRepo.Name,
			SourcePath:       path,
			LastUpdated:      lastUpdated,
			HasLastUpdated:   hasUpdateTime,
			Format:           RecordFormatJSON,
			KeyPath:          sourceRepo.KeyPath,
			Strict:           sourceRepo.Strictness,
			IsReimport:       !hasUpdateTime,
		}

		return true
	})

	// Set the last updated time to the minimum of:
	// - the time of run
	// - the max vulnerability modified time
	// - the Last-Modified time of the REST API response
	// This is to be more robust in case of misbehaving servers.
	timeToUpdate := timeOfRun
	if !maxModified.IsZero() && maxModified.Before(timeToUpdate) {
		timeToUpdate = maxModified
	}
	if !lastModTime.IsZero() && lastModTime.Before(timeToUpdate) {
		timeToUpdate = lastModTime
	}
	sourceRepo.REST.LastUpdated = &timeToUpdate
	sourceRepo.REST.IgnoreLastImportTime = false
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.ErrorContext(ctx, "Failed to update source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))

		return err
	}
	logger.InfoContext(ctx, "Finished importing REST source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("url", sourceRepo.REST.URL))

	return nil
}

func handleDeleteREST(ctx context.Context, ch chan<- WorkItem, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeREST || sourceRepo.REST == nil {
		return errors.New("invalid SourceRepository for REST deletion")
	}

	logger.InfoContext(ctx, "Processing REST deletions",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))

	// Fetch current IDs from REST API
	req, err := http.NewRequest(http.MethodGet, sourceRepo.REST.URL, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	resp, err := config.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to fetch REST API: %d", resp.StatusCode)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	result := gjson.ParseBytes(data)
	if !result.IsArray() {
		return errors.New("REST API response is not an array")
	}

	idsInREST := make(map[string]bool)
	result.ForEach(func(_, vuln gjson.Result) bool {
		if id := vuln.Get("id"); id.Exists() {
			idsInREST[id.String()] = true
		}

		return true
	})

	// Get all non-withdrawn vulnerabilities in Datastore for this source
	vulnsInDatastore := make([]*models.VulnSourceRef, 0, len(idsInREST))
	for entry, err := range config.VulnerabilityStore.ListBySource(ctx, sourceRepo.Name, true) {
		if err != nil {
			return err
		}
		vulnsInDatastore = append(vulnsInDatastore, entry)
	}

	if len(vulnsInDatastore) == 0 {
		logger.InfoContext(ctx, "No vulnerabilities found in Datastore for source", slog.String("source", sourceRepo.Name))

		return nil
	}

	// Reconcile
	var toDelete []*models.VulnSourceRef
	for _, entry := range vulnsInDatastore {
		// Path in REST is usually just the ID (without extension, or inferred from ID)
		// We check against the ID map
		if !idsInREST[entry.ID] {
			toDelete = append(toDelete, entry)
		}
	}

	if len(toDelete) == 0 {
		logger.InfoContext(ctx, "No vulnerabilities to delete", slog.String("source", sourceRepo.Name))

		return nil
	}

	// Safety Check
	threshold := config.DeleteThreshold
	if sourceRepo.REST.IgnoreDeletionThreshold {
		threshold = 101.0
	}
	percentage := (float64(len(toDelete)) / float64(len(vulnsInDatastore))) * 100.0
	if percentage >= threshold {
		logger.ErrorContext(ctx, "Cowardly refusing to delete missing records (threshold exceeded)",
			slog.String("source", sourceRepo.Name),
			slog.Int("to_delete", len(toDelete)),
			slog.Int("total", len(vulnsInDatastore)),
			slog.Float64("percentage", percentage),
			slog.Float64("threshold", threshold))

		return errors.New("deletion threshold exceeded")
	}

	// Trigger deletions
	for _, entry := range toDelete {
		ch <- WorkItem{
			Context: ctx,
			SourceRecord: restSourceRecord{
				cl:      config.HTTPClient,
				urlBase: sourceRepo.Link,
				urlPath: entry.Path,
			},
			SourceRepository: entry.Source,
			SourcePath:       entry.Path,
			IsDeleted:        true,
		}
	}

	return nil
}

// checkHEAD performs a HEAD request to check for updates
func checkHEAD(ctx context.Context, config Config, sourceRepo *models.SourceRepository) (time.Time, error) {
	req, err := http.NewRequest(http.MethodHead, sourceRepo.REST.URL, nil)
	if err != nil {
		return time.Time{}, err
	}
	req = req.WithContext(ctx)
	resp, err := config.HTTPClient.Do(req)
	if err != nil {
		return time.Time{}, err
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		logger.WarnContext(ctx, "HEAD request failed, falling back to GET",
			slog.String("source", sourceRepo.Name),
			slog.Int("status_code", resp.StatusCode),
			slog.String("url", sourceRepo.REST.URL))

		return time.Time{}, nil
	}

	lastModified := resp.Header.Get("Last-Modified")
	if lastModified == "" {
		logger.WarnContext(ctx, "No Last-Modified header found.",
			slog.String("source", sourceRepo.Name),
			slog.String("url", sourceRepo.REST.URL))

		return time.Time{}, nil
	}

	lastModTime, err := time.Parse(time.RFC1123, lastModified)
	if err != nil {
		logger.WarnContext(ctx, "Failed to parse Last-Modified header.",
			slog.String("source", sourceRepo.Name),
			slog.String("url", sourceRepo.REST.URL),
			slog.Any("error", err))

		return time.Time{}, nil
	}

	return lastModTime, nil
}
