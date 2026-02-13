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
	cl               *http.Client
	urlBase          string
	urlPath          string
	keyPath          string
	hasUpdateTime    bool
	lastUpdated      time.Time
	sourceRepository string
}

var _ SourceRecord = restSourceRecord{}

func (r restSourceRecord) Open(ctx context.Context) (io.ReadCloser, error) {
	u, err := url.JoinPath(r.urlBase, r.urlPath)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("GET", u, nil)
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

func (r restSourceRecord) KeyPath() string {
	return r.keyPath
}

func (r restSourceRecord) Format() RecordFormat {
	return RecordFormatJSON
}

func (r restSourceRecord) LastUpdated() (time.Time, bool) {
	return r.lastUpdated, r.hasUpdateTime
}

func (r restSourceRecord) SourceRepository() string {
	return r.sourceRepository
}

func (r restSourceRecord) SourcePath() string {
	return r.urlPath
}

func (r restSourceRecord) ShouldSendModifiedTime() bool {
	return r.hasUpdateTime
}

func (r restSourceRecord) IsDeleted() bool {
	return false
}

func handleImportREST(ctx context.Context, ch chan<- SourceRecord, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeREST || sourceRepo.REST == nil {
		return errors.New("invalid SourceRepository for REST import")
	}
	logger.Info("Importing REST source repository",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))

	compiledIgnorePatterns := compileIgnorePatterns(sourceRepo)
	hasUpdateTime := false
	var lastUpdated time.Time
	if !sourceRepo.REST.IgnoreLastImportTime && sourceRepo.REST.LastUpdated != nil {
		lastUpdated = *sourceRepo.REST.LastUpdated
		hasUpdateTime = true
	}
	timeOfRun := time.Now()
	if hasUpdateTime {
		// HEAD request to check if there are updates
		req, err := http.NewRequest("HEAD", sourceRepo.REST.URL, nil)
		if err != nil {
			return err
		}
		req = req.WithContext(ctx)
		resp, err := config.HTTPClient.Do(req)
		if err != nil {
			return err
		}
		resp.Body.Close()
		lastModified := resp.Header.Get("Last-Modified")
		mod, err := time.Parse(time.RFC1123, lastModified)
		if err == nil && mod.Before(lastUpdated) {
			logger.Info("No changes since last update.",
				slog.String("source", sourceRepo.Name),
				slog.String("url", sourceRepo.REST.URL))
			return nil
		}
		if lastModified == "" {
			logger.Warn("No Last-Modified header found.",
				slog.String("source", sourceRepo.Name),
				slog.String("url", sourceRepo.REST.URL))
		} else if err != nil {
			logger.Warn("Failed to parse Last-Modified header.",
				slog.String("source", sourceRepo.Name),
				slog.String("url", sourceRepo.REST.URL),
				slog.String("error", err.Error()))
		}
	}

	req, err := http.NewRequest("GET", sourceRepo.REST.URL, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	resp, err := config.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		logger.Error("Failed to fetch REST API", slog.String("source", sourceRepo.Name), slog.Int("status_code", resp.StatusCode), slog.String("url", sourceRepo.REST.URL))
		return fmt.Errorf("failed to fetch REST API: %d for %s", resp.StatusCode, sourceRepo.REST.URL)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Failed to read REST API response", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL), slog.String("error", err.Error()))
		return err
	}
	result := gjson.ParseBytes(data)
	if !result.IsArray() {
		logger.Error("REST API response is not an array", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))
		return fmt.Errorf("REST API response is not an array for %s", sourceRepo.REST.URL)
	}
	result.ForEach(func(_, vuln gjson.Result) bool {
		id := vuln.Get("id")
		if !id.Exists() {
			logger.Error("Vulnerability missing id", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))
			return true
		}
		modified := vuln.Get("modified")
		if !modified.Exists() {
			logger.Error("Vulnerability missing modified", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL), slog.String("id", id.String()))
			return true
		}
		mod, err := time.Parse(time.RFC3339, modified.String())
		if err != nil {
			logger.Error("Failed to parse modified", slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL), slog.String("id", id.String()), slog.String("error", err.Error()))
			return true
		}
		if hasUpdateTime && mod.Before(lastUpdated) {
			return true
		}
		if shouldIgnore(id.String(), sourceRepo.IDPrefixes, compiledIgnorePatterns) {
			return true
		}
		ch <- restSourceRecord{
			cl:               config.HTTPClient,
			urlBase:          sourceRepo.Link,
			urlPath:          id.String() + sourceRepo.Extension,
			keyPath:          sourceRepo.KeyPath,
			hasUpdateTime:    hasUpdateTime,
			lastUpdated:      lastUpdated,
			sourceRepository: sourceRepo.Name,
		}
		return true
	})

	sourceRepo.REST.LastUpdated = &timeOfRun
	sourceRepo.REST.IgnoreLastImportTime = false
	if err := config.SourceRepoStore.Update(ctx, sourceRepo.Name, sourceRepo); err != nil {
		logger.Error("Failed to update source repository", slog.Any("error", err), slog.String("source", sourceRepo.Name))
		return err
	}
	logger.Info("Finished importing REST source repository",
		slog.String("source", sourceRepo.Name),
		slog.String("url", sourceRepo.REST.URL))

	return nil
}

func handleDeleteREST(ctx context.Context, config Config, sourceRepo *models.SourceRepository) error {
	if sourceRepo.Type != models.SourceRepositoryTypeREST || sourceRepo.REST == nil {
		return errors.New("invalid SourceRepository for REST deletion")
	}

	logger.Info("Processing REST deletions",
		slog.String("source", sourceRepo.Name), slog.String("url", sourceRepo.REST.URL))

	// Fetch current IDs from REST API
	req, err := http.NewRequest("GET", sourceRepo.REST.URL, nil)
	if err != nil {
		return err
	}
	req = req.WithContext(ctx)
	resp, err := config.HTTPClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
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
	var vulnsInDatastore []*models.VulnSourceRef
	for entry, err := range config.VulnerabilityStore.ListBySource(ctx, sourceRepo.Name, true) {
		if err != nil {
			return err
		}
		vulnsInDatastore = append(vulnsInDatastore, entry)
	}

	if len(vulnsInDatastore) == 0 {
		logger.Info("No vulnerabilities found in Datastore for source", slog.String("source", sourceRepo.Name))
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
		logger.Info("No vulnerabilities to delete", slog.String("source", sourceRepo.Name))
		return nil
	}

	// Safety Check
	threshold := config.DeleteThreshold
	if sourceRepo.REST.IgnoreDeletionThreshold {
		threshold = 101.0
	}
	percentage := (float64(len(toDelete)) / float64(len(vulnsInDatastore))) * 100.0
	if percentage >= threshold {
		logger.Error("Cowardly refusing to delete missing records (threshold exceeded)",
			slog.String("source", sourceRepo.Name),
			slog.Int("to_delete", len(toDelete)),
			slog.Int("total", len(vulnsInDatastore)),
			slog.Float64("percentage", percentage),
			slog.Float64("threshold", threshold))
		return errors.New("deletion threshold exceeded")
	}

	// Trigger deletions
	for _, entry := range toDelete {
		logger.Info("Requesting deletion of REST entry",
			slog.String("source", entry.Source),
			slog.String("id", entry.ID),
			slog.String("path", entry.Path))
		if err := sendDeletionToWorker(ctx, config, entry.Source, entry.Path); err != nil {
			logger.Error("Failed to send deletion to worker",
				slog.String("source", entry.Source),
				slog.String("id", entry.ID),
				slog.Any("error", err))
		}
	}

	return nil
}
