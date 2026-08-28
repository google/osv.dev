package gcs

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	"cloud.google.com/go/storage"
	"github.com/google/osv.dev/go/internal/models"
)

const (
	maxResponseSize = 10 * 1024 * 1024 // 10 MB
)

var cveIDRegex = regexp.MustCompile(`^(?i)CVE-(\d{4})-(\d+)$`)

type sourceConfig struct {
	Bucket       string
	PathTemplate string
}

var gcsSources = map[string]sourceConfig{
	"test-nvd":          {Bucket: "osv-test-cve-osv-conversion", PathTemplate: "nvd-osv/%s.json"},
	"test-cve5":         {Bucket: "osv-test-cve-osv-conversion", PathTemplate: "cve5/%s.json"},
	"test-osv":          {Bucket: "osv-test-cve-osv-conversion", PathTemplate: "osv-output/%s.json"},
	"test-nvd-metrics":  {Bucket: "osv-test-cve-osv-conversion", PathTemplate: "nvd-osv/%s.metrics.json"},
	"test-cve5-metrics": {Bucket: "osv-test-cve-osv-conversion", PathTemplate: "cve5/%s.metrics.json"},
	"prod-nvd":          {Bucket: "cve-osv-conversion", PathTemplate: "nvd-osv/%s.json"},
	"prod-cve5":         {Bucket: "cve-osv-conversion", PathTemplate: "cve5/%s.json"},
	"prod-osv":          {Bucket: "cve-osv-conversion", PathTemplate: "osv-output/%s.json"},
	"prod-nvd-metrics":  {Bucket: "cve-osv-conversion", PathTemplate: "nvd-osv/%s.metrics.json"},
	"prod-cve5-metrics": {Bucket: "cve-osv-conversion", PathTemplate: "cve5/%s.metrics.json"},
}

// TriageStore implements models.TriageStore for reading CVE data from GCS and upstream APIs.
type TriageStore struct {
	client     *storage.Client
	httpClient *http.Client
}

var _ models.TriageStore = (*TriageStore)(nil)

// NewTriageStore creates a new TriageStore.
func NewTriageStore(client *storage.Client) *TriageStore {
	return &TriageStore{
		client: client,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

// GetFile retrieves the raw JSON content for a given source and CVE ID.
func (s *TriageStore) GetFile(ctx context.Context, source, cveID string) ([]byte, error) {
	cveID = strings.ToUpper(cveID)
	matches := cveIDRegex.FindStringSubmatch(cveID)
	if len(matches) < 3 {
		return nil, fmt.Errorf("%w: invalid CVE ID format: %s", models.ErrInvalidArgument, cveID)
	}

	// Handle GCS sources
	if cfg, ok := gcsSources[source]; ok {
		if s.client == nil {
			return nil, errors.New("storage client is not configured")
		}
		path := fmt.Sprintf(cfg.PathTemplate, cveID)
		r, err := s.client.Bucket(cfg.Bucket).Object(path).NewReader(ctx)
		if errors.Is(err, storage.ErrObjectNotExist) {
			return nil, models.ErrNotFound
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read from GCS (%s): %w", source, err)
		}
		defer r.Close()

		return io.ReadAll(r)
	}

	// Handle external API sources
	var url string
	switch source {
	case "cve":
		year := matches[1]
		seq := matches[2]
		seqPrefix := "0"
		if len(seq) > 3 {
			seqPrefix = seq[:len(seq)-3]
		}
		url = fmt.Sprintf("https://raw.githubusercontent.com/CVEProject/cvelistV5/refs/heads/main/cves/%s/%sxxx/%s.json", year, seqPrefix, cveID)
	case "nvd":
		url = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=" + cveID
	default:
		return nil, fmt.Errorf("%w: invalid source: %s", models.ErrInvalidArgument, source)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch from external API (%s): %w", source, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, models.ErrNotFound
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("external API returned status %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
}
