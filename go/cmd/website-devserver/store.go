package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/osv.dev/go/internal/database/datastore"
	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/protobuf/encoding/protojson"
	"sigs.k8s.io/yaml"
)

// Metadata represents optional metadata stored in companion .meta.yaml files.
type Metadata struct {
	Source string `json:"source" yaml:"source"`
	Path   string `json:"path"   yaml:"path"`
}

// DevStore implements all models.*Store interfaces backed by live filesystem reads.
type DevStore struct {
	models.UnimplementedVulnerabilityStore
	models.UnimplementedRelationsStore
	models.UnimplementedVulnerabilitySearchStore
	models.UnimplementedSourceRepositoryStore
	models.UnimplementedLinterStore
	models.UnimplementedTriageStore

	dataDir     string
	sourcesFile string

	mu          sync.RWMutex
	sourceRepos map[string]*models.SourceRepository
}

// NewDevStore initializes a new DevStore.
func NewDevStore(dataDir, sourcesFile string) (*DevStore, error) {
	if dataDir == "" {
		return nil, errors.New("dataDir is required")
	}

	ds := &DevStore{
		dataDir:     dataDir,
		sourcesFile: sourcesFile,
		sourceRepos: make(map[string]*models.SourceRepository),
	}

	ds.loadSources()

	return ds, nil
}

func (ds *DevStore) loadSources() {
	ds.mu.Lock()
	defer ds.mu.Unlock()

	// Default fallback source
	ds.sourceRepos["test"] = &models.SourceRepository{
		Name: "test",
		Link: "https://github.com/google/osv.dev/blob/master/",
	}

	loadFile := func(filePath string) {
		if filePath == "" {
			return
		}
		data, err := os.ReadFile(filePath)
		if err != nil {
			return
		}

		var rawSources []struct {
			Name      string `json:"name"       yaml:"name"`
			Link      string `json:"link"       yaml:"link"`
			HumanLink string `json:"human_link" yaml:"human_link"`
		}

		if err := yaml.Unmarshal(data, &rawSources); err != nil {
			return
		}

		for _, s := range rawSources {
			if s.Name != "" {
				ds.sourceRepos[s.Name] = &models.SourceRepository{
					Name:      s.Name,
					Link:      s.Link,
					HumanLink: s.HumanLink,
				}
			}
		}
	}

	loadFile(ds.sourcesFile)
	dataSourcesFile := filepath.Join(ds.dataDir, "sources.yaml")
	if dataSourcesFile != ds.sourcesFile {
		loadFile(dataSourcesFile)
	}
}

// readRecordFromFile reads and unmarshals an OSV record from a JSON file and its companion .meta.yaml.
func readRecordFromFile(jsonPath string) (*osvschema.Vulnerability, *Metadata, error) {
	fileBytes, err := os.ReadFile(jsonPath)
	if err != nil {
		return nil, nil, err
	}

	vuln := &osvschema.Vulnerability{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(fileBytes, vuln); err != nil {
		return nil, nil, fmt.Errorf("failed to unmarshal vulnerability at %s: %w", jsonPath, err)
	}

	meta := &Metadata{
		Source: "test",
		Path:   filepath.Base(jsonPath),
	}

	metaPath := strings.TrimSuffix(jsonPath, ".json") + ".meta.yaml"
	if metaBytes, err := os.ReadFile(metaPath); err == nil {
		_ = yaml.Unmarshal(metaBytes, meta)
	}

	if meta.Source == "" {
		meta.Source = "test"
	}
	if meta.Path == "" {
		meta.Path = filepath.Base(jsonPath)
	}

	return vuln, meta, nil
}

// readRecordFromDisk finds and reads an OSV record and its optional companion .meta.yaml.
func (ds *DevStore) readRecordFromDisk(id string) (*osvschema.Vulnerability, *Metadata, error) {
	// Exact filename match
	exactPath := filepath.Join(ds.dataDir, id+".json")
	if _, err := os.Stat(exactPath); err == nil {
		return readRecordFromFile(exactPath)
	}

	// Case-insensitive match in dataDir
	entries, err := os.ReadDir(ds.dataDir)
	if err != nil {
		return nil, nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		if strings.EqualFold(strings.TrimSuffix(entry.Name(), ".json"), id) {
			return readRecordFromFile(filepath.Join(ds.dataDir, entry.Name()))
		}
	}

	return nil, nil, models.ErrNotFound
}

// loadAllVulns reads all valid vulnerability records from the data directory.
func (ds *DevStore) loadAllVulns() []*osvschema.Vulnerability {
	entries, err := os.ReadDir(ds.dataDir)
	if err != nil {
		return nil
	}

	var records []*osvschema.Vulnerability
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}

		vuln, _, err := readRecordFromFile(filepath.Join(ds.dataDir, entry.Name()))
		if err == nil && vuln != nil && vuln.GetId() != "" {
			records = append(records, vuln)
		}
		if err != nil {
			slog.Error("Failed to read vulnerability",
				slog.String("path", filepath.Join(ds.dataDir, entry.Name())),
				slog.Any("err", err),
			)
		}
	}

	return records
}

// =========================================================================
// models.VulnerabilityStore Implementation
// =========================================================================

func (ds *DevStore) GetFull(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	vuln, _, err := ds.readRecordFromDisk(id)

	return vuln, err
}

func (ds *DevStore) GetWithMetadata(_ context.Context, id string) (*osvschema.Vulnerability, *models.VulnSourceRef, error) {
	vuln, meta, err := ds.readRecordFromDisk(id)
	if err != nil {
		return nil, nil, err
	}

	ref := &models.VulnSourceRef{
		ID:          vuln.GetId(),
		Source:      meta.Source,
		Path:        meta.Path,
		ModifiedRaw: vuln.GetModified().AsTime(),
	}

	return vuln, ref, nil
}

func (ds *DevStore) GetModified(ctx context.Context, id string) (time.Time, error) {
	vuln, err := ds.GetFull(ctx, id)
	if err != nil {
		return time.Time{}, err
	}

	return vuln.GetModified().AsTime(), nil
}

func (ds *DevStore) Exists(ctx context.Context, id string) (bool, error) {
	vuln, err := ds.GetFull(ctx, id)
	if errors.Is(err, models.ErrNotFound) {
		return false, nil
	}

	return vuln != nil, err
}

// =========================================================================
// models.RelationsStore Implementation
// =========================================================================

// GetAliases returns the aliases for the given vulnerability.
// For the dev server, we assume the vulnerability's aliases field in its JSON
// record is already complete and fully populated, returning it directly without
// computing transitive alias closures across all records.
func (ds *DevStore) GetAliases(_ context.Context, id string) (*models.GetAliasResult, error) {
	vuln, _, err := ds.readRecordFromDisk(id)
	if err != nil {
		return nil, err
	}

	aliases := slices.Clone(vuln.GetAliases())
	slices.Sort(aliases)

	return &models.GetAliasResult{
		Aliases:  aliases,
		Modified: vuln.GetModified().AsTime(),
	}, nil
}

func (ds *DevStore) getDirectUpstream(id string) []string {
	vuln, _, err := ds.readRecordFromDisk(id)
	if err != nil || vuln == nil {
		return nil
	}

	return vuln.GetUpstream()
}

func (ds *DevStore) GetUpstreamHierarchy(_ context.Context, id string) (*models.Hierarchy, error) {
	directUps := ds.getDirectUpstream(id)
	if len(directUps) == 0 {
		return nil, models.ErrNotFound
	}

	rawHierarchy := make(map[string][]string)
	visited := make(map[string]bool)
	queue := []string{id}

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		if visited[curr] {
			continue
		}
		visited[curr] = true

		ups := ds.getDirectUpstream(curr)
		if len(ups) > 0 {
			rawHierarchy[curr] = ups
			for _, u := range ups {
				if !visited[u] {
					queue = append(queue, u)
				}
			}
		}
	}

	return datastore.ComputeUpstreamHierarchy(id, rawHierarchy)
}

func (ds *DevStore) GetDownstreamHierarchy(_ context.Context, id string) (*models.Hierarchy, error) {
	allVulns := ds.loadAllVulns()
	allUpstreams := make(map[string][]string)
	for _, v := range allVulns {
		if len(v.GetUpstream()) > 0 {
			allUpstreams[v.GetId()] = v.GetUpstream()
		}
	}

	// Find reachable downstreams for id
	downstreams := make(map[string][]string)
	queue := []string{id}
	visited := make(map[string]bool)
	visited[id] = true

	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]

		for childID, upstreams := range allUpstreams {
			if slices.Contains(upstreams, curr) {
				downstreams[childID] = upstreams
				if !visited[childID] {
					visited[childID] = true
					queue = append(queue, childID)
				}
			}
		}
	}

	if len(downstreams) == 0 {
		return nil, models.ErrNotFound
	}

	return datastore.ComputeDownstreamHierarchy(id, downstreams)
}

// =========================================================================
// models.SourceRepositoryStore Implementation
// =========================================================================

func (ds *DevStore) Get(_ context.Context, name string) (*models.SourceRepository, error) {
	ds.mu.RLock()
	defer ds.mu.RUnlock()

	repo, ok := ds.sourceRepos[name]
	if !ok {
		return nil, models.ErrNotFound
	}

	return repo, nil
}

// =========================================================================
// models.VulnerabilitySearchStore Implementation
// =========================================================================

func (ds *DevStore) Search(_ context.Context, query models.VulnerabilitySearchQuery) (*models.VulnerabilitySearchResult, error) {
	allVulns := ds.loadAllVulns()
	listed := make([]*models.ListedVulnerability, 0, len(allVulns))

	q := strings.ToLower(strings.TrimSpace(query.Query))
	eco := strings.TrimSpace(query.Ecosystem)

	for _, v := range allVulns {
		// Filter by Ecosystem
		if eco != "" {
			matchedEco := false
			for _, a := range v.GetAffected() {
				aEco := a.GetPackage().GetEcosystem()
				topEco, _, _ := strings.Cut(aEco, ":")
				if strings.EqualFold(aEco, eco) || strings.EqualFold(topEco, eco) {
					matchedEco = true

					break
				}
			}
			if !matchedEco {
				continue
			}
		}

		// Filter by Query (ID, Summary, Details, Aliases, Package Name, Repository URL)
		if q != "" {
			matchedQuery := false
			if strings.Contains(strings.ToLower(v.GetId()), q) ||
				strings.Contains(strings.ToLower(v.GetSummary()), q) ||
				strings.Contains(strings.ToLower(v.GetDetails()), q) {
				matchedQuery = true
			}
			if !matchedQuery {
				for _, alias := range v.GetAliases() {
					if strings.Contains(strings.ToLower(alias), q) {
						matchedQuery = true

						break
					}
				}
			}
			if !matchedQuery {
				for _, a := range v.GetAffected() {
					if strings.Contains(strings.ToLower(a.GetPackage().GetName()), q) {
						matchedQuery = true

						break
					}
					for _, r := range a.GetRanges() {
						if strings.Contains(strings.ToLower(r.GetRepo()), q) {
							matchedQuery = true

							break
						}
					}
					if matchedQuery {
						break
					}
				}
			}
			if !matchedQuery {
				continue
			}
		}

		// Build ListedVulnerability
		var packages []models.Package
		isFixed := false
		for _, a := range v.GetAffected() {
			pkg := models.Package{
				Package: a.GetPackage(),
			}
			for _, r := range a.GetRanges() {
				if r.GetType() == osvschema.Range_GIT && r.GetRepo() != "" {
					pkg.Repo = r.GetRepo()
				}
				for _, ev := range r.GetEvents() {
					if ev.GetFixed() != "" {
						isFixed = true
					}
				}
			}
			packages = append(packages, pkg)
		}

		listed = append(listed, &models.ListedVulnerability{
			ID:         v.GetId(),
			Published:  v.GetPublished().AsTime(),
			Summary:    v.GetSummary(),
			IsFixed:    isFixed,
			Severities: v.GetSeverity(),
			Packages:   packages,
		})
	}

	// Sort Published descending, tie breaker on ID descending
	slices.SortFunc(listed, func(a, b *models.ListedVulnerability) int {
		aTime := a.Published.Truncate(time.Microsecond)
		bTime := b.Published.Truncate(time.Microsecond)
		if !aTime.Equal(bTime) {
			if aTime.After(bTime) {
				return -1
			}

			return 1
		}

		return strings.Compare(b.ID, a.ID)
	})

	pageSize := query.PageSize
	if pageSize <= 0 {
		pageSize = 16
	}

	// Keyset (cursor) pagination, with fallback to legacy 1-based page numbers for interface and handler compatibility.
	startIndex := 0
	if !query.AfterTime.IsZero() {
		afterTime := query.AfterTime.Truncate(time.Microsecond)
		found := false
		for i, item := range listed {
			itemTime := item.Published.Truncate(time.Microsecond)
			if itemTime.Before(afterTime) ||
				(itemTime.Equal(afterTime) && strings.Compare(item.ID, query.AfterID) < 0) {
				startIndex = i
				found = true

				break
			}
		}
		if !found {
			return &models.VulnerabilitySearchResult{
				Vulnerabilities: []*models.ListedVulnerability{},
			}, nil
		}
	} else if query.Page > 1 {
		startIndex = (query.Page - 1) * pageSize
	}

	if startIndex >= len(listed) {
		return &models.VulnerabilitySearchResult{
			Vulnerabilities: []*models.ListedVulnerability{},
		}, nil
	}

	endIndex := startIndex + pageSize
	hasMore := endIndex < len(listed)
	if endIndex > len(listed) {
		endIndex = len(listed)
	}

	pageItems := listed[startIndex:endIndex]

	var nextTime time.Time
	var nextID string
	if hasMore && len(pageItems) > 0 {
		lastItem := pageItems[len(pageItems)-1]
		nextTime = lastItem.Published.Truncate(time.Microsecond)
		nextID = lastItem.ID
	}

	// Exact ID match prioritization on page 1
	if query.AfterTime.IsZero() && query.Page <= 1 && q != "" && len(pageItems) > 1 {
		for i, v := range pageItems {
			if strings.EqualFold(v.ID, query.Query) {
				if i > 0 {
					match := pageItems[i]
					copy(pageItems[1:i+1], pageItems[0:i])
					pageItems[0] = match
				}

				break
			}
		}
	}

	return &models.VulnerabilitySearchResult{
		Vulnerabilities: pageItems,
		NextAfterTime:   nextTime,
		NextAfterID:     nextID,
	}, nil
}

func (ds *DevStore) Autocomplete(_ context.Context, prefix string, limit int) ([]string, error) {
	if limit <= 0 {
		limit = 10
	}
	p := strings.ToLower(strings.TrimSpace(prefix))
	if p == "" {
		return nil, nil
	}

	allVulns := ds.loadAllVulns()
	seen := make(map[string]struct{})
	var results []string

	for _, v := range allVulns {
		if strings.HasPrefix(strings.ToLower(v.GetId()), p) {
			if _, ok := seen[v.GetId()]; !ok {
				seen[v.GetId()] = struct{}{}
				results = append(results, v.GetId())
			}
		}
		for _, a := range v.GetAffected() {
			pkgName := a.GetPackage().GetName()
			if pkgName != "" && strings.HasPrefix(strings.ToLower(pkgName), p) {
				if _, ok := seen[pkgName]; !ok {
					seen[pkgName] = struct{}{}
					results = append(results, pkgName)
				}
			}
			for _, r := range a.GetRanges() {
				repo := r.GetRepo()
				if repo != "" && strings.HasPrefix(strings.ToLower(repo), p) {
					if _, ok := seen[repo]; !ok {
						seen[repo] = struct{}{}
						results = append(results, repo)
					}
				}
			}
		}
	}

	slices.Sort(results)
	if len(results) > limit {
		results = results[:limit]
	}

	return results, nil
}

func (ds *DevStore) EcosystemCounts(_ context.Context) ([]models.EcosystemCount, error) {
	allVulns := ds.loadAllVulns()
	ecoCounts := make(map[string]int)

	for _, v := range allVulns {
		seenInVuln := make(map[string]struct{})
		for _, a := range v.GetAffected() {
			eco := a.GetPackage().GetEcosystem()
			if eco != "" {
				topEco, _, _ := strings.Cut(eco, ":")
				if topEco != "" {
					seenInVuln[topEco] = struct{}{}
				}
			}
		}
		for eco := range seenInVuln {
			ecoCounts[eco]++
		}
	}

	results := make([]models.EcosystemCount, 0, len(ecoCounts))
	for eco, count := range ecoCounts {
		results = append(results, models.EcosystemCount{
			Name:  eco,
			Count: count,
		})
	}

	slices.SortFunc(results, func(a, b models.EcosystemCount) int {
		return strings.Compare(a.Name, b.Name)
	})

	return results, nil
}

// =========================================================================
// models.LinterStore & models.TriageStore Implementation
// =========================================================================

func (ds *DevStore) ListSources(_ context.Context) ([]string, error) {
	return []string{"cve-osv", "ghsa", "ubuntu", "debian", "suse"}, nil
}

type linterFindingsData struct {
	Source   string   `json:"source"`
	Findings []string `json:"findings"`
}

func (ds *DevStore) GetFindings(_ context.Context, source string) ([]byte, error) {
	findings := linterFindingsData{
		Source:   source,
		Findings: []string{},
	}
	data, err := json.Marshal(findings)
	if err != nil {
		return nil, err
	}

	return data, nil
}

func (ds *DevStore) GetFile(ctx context.Context, source, cveID string) ([]byte, error) {
	vuln, _, err := ds.readRecordFromDisk(cveID)
	if err == nil && vuln != nil {
		return protojson.Marshal(vuln)
	}

	logger.InfoContext(ctx, "devstore: triage proxy file not found locally", slog.String("source", source), slog.String("id", cveID))

	return nil, models.ErrNotFound
}
