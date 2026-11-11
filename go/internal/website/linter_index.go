package website

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unique"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

const (
	defaultLinterCacheTTL   = 2 * time.Minute
	linterDevCacheTTL       = 2 * time.Second
	linterBackgroundRefresh = 90 * time.Second
	linterRefreshTimeout    = 2 * time.Minute
	linterTimestampRefresh  = 30 * time.Minute
	linterColdGraceWait     = 150 * time.Millisecond
	linterEnrichTimeout     = 10 * time.Minute
	linterFetchConcurrency  = 16
	defaultLinterPageSize   = 15
	maxLinterPageSize       = 100
)

var knownRuleLabels = map[string]string{
	"SCH:001":    "Invalid JSON / Schema",
	"REC:001":    "Invalid Record",
	"REC:002":    "Invalid Aliases",
	"REC:003":    "Invalid Upstream",
	"REC:004":    "Invalid Related",
	"REC:005":    "Invalid Summary / Details",
	"RNG:001":    "Invalid Range",
	"RNG:002":    "Overlapping / Invalid Range Events",
	"PKG:001":    "Invalid Package",
	"PKG:002":    "Invalid Version",
	"PKG:003":    "Invalid PURL",
	"COMMIT:001": "Invalid Commit",
	"CVE:001":    "Bad Aliased CVE",
	"DEL:001":    "Deleted Record",
}

// LinterFindingDetail represents an individual linter rule violation on a vulnerability record.
type LinterFindingDetail struct {
	Code    string `json:"Code"`
	Message string `json:"Message"`
}

// LinterIssueSummary represents a single vulnerability row in paginated linter query results.
type LinterIssueSummary struct {
	BugID       string                `json:"bug_id"`
	Source      string                `json:"source"`
	Codes       []string              `json:"codes"`
	LastAttempt string                `json:"last_attempt,omitempty"`
	Details     []LinterFindingDetail `json:"details"`
}

// LinterSourceFacet holds the dynamic issue count for a Home Database source.
type LinterSourceFacet struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// LinterRuleFacet holds metadata and dynamic issue count for a specific linter rule code.
type LinterRuleFacet struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// LinterFacets holds dynamic facet counts across sources and rules.
type LinterFacets struct {
	TotalForSources int                 `json:"total_for_sources"`
	Sources         []LinterSourceFacet `json:"sources"`
	TotalForRules   int                 `json:"total_for_rules"`
	Rules           []LinterRuleFacet   `json:"rules"`
}

// LinterQueryResponse is the JSON payload returned by GET /linter-findings/query.
type LinterQueryResponse struct {
	Issues   []LinterIssueSummary `json:"issues"`
	Total    int                  `json:"total"`
	Page     int                  `json:"page"`
	PageSize int                  `json:"page_size"`
	Facets   LinterFacets         `json:"facets"`
}

type linterQueryParams struct {
	Source   string
	Code     string
	Query    string
	Order    string // "desc" (default) or "asc"
	Page     int
	PageSize int
}

type linterIssue struct {
	bugID       string
	bugIDLower  string
	source      string
	codes       []string
	lastAttempt int64
	findings    []LinterFindingDetail
}

type linterSnapshot struct {
	loadedAt        time.Time
	hasGenerations  bool
	timestampsReady bool
	sources         []string
	rules           []string
	issues          []linterIssue // Pre-sorted by (lastAttempt DESC, bugID ASC)
}

type cachedSourceFindings struct {
	updated    time.Time
	generation int64
	bugs       map[string][]LinterFindingDetail
}

type linterIndex struct {
	linterStore         models.LinterStore
	sourceRepoStore     models.SourceRepositoryStore
	importFindingsStore models.ImportFindingsStore
	cacheTTL            time.Duration

	snapshot atomic.Pointer[linterSnapshot]
	sf       singleflight.Group

	mu                sync.Mutex
	sourceCache       map[string]cachedSourceFindings
	knownSources      []string
	timestamps        map[string]int64
	timestampsReady   bool
	timestampsUpdated time.Time
	enriching         bool
	enrichDone        chan struct{}
}

func newLinterIndex(
	linterStore models.LinterStore,
	sourceRepoStore models.SourceRepositoryStore,
	importFindingsStore models.ImportFindingsStore,
	cacheTTL time.Duration,
) *linterIndex {
	if cacheTTL <= 0 {
		cacheTTL = defaultLinterCacheTTL
	}

	return &linterIndex{
		linterStore:         linterStore,
		sourceRepoStore:     sourceRepoStore,
		importFindingsStore: importFindingsStore,
		cacheTTL:            cacheTTL,
		sourceCache:         make(map[string]cachedSourceFindings),
		timestampsReady:     importFindingsStore == nil,
	}
}

func internStr(s string) string {
	return unique.Make(s).Value()
}

func ruleLabel(code string) string {
	if lbl, ok := knownRuleLabels[code]; ok {
		return lbl
	}

	return code
}

func (idx *linterIndex) rebuildLocked() *linterSnapshot {
	snap := buildLinterSnapshot(idx.knownSources, idx.sourceCache, idx.timestamps, idx.timestampsReady)
	idx.snapshot.Store(snap)

	return snap
}

func (idx *linterIndex) triggerRefresh(baseCtx context.Context) <-chan singleflight.Result {
	return idx.sf.DoChan("refresh", func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(baseCtx), linterRefreshTimeout)
		defer cancel()

		return idx.refresh(refreshCtx)
	})
}

func (idx *linterIndex) getSnapshot(ctx context.Context) (*linterSnapshot, error) {
	snap := idx.snapshot.Load()
	if snap != nil {
		ttl := idx.cacheTTL
		if !snap.hasGenerations {
			ttl = min(ttl, linterDevCacheTTL)
		}
		if !snap.timestampsReady {
			idx.mu.Lock()
			enriching := idx.enriching
			idx.mu.Unlock()
			if !enriching {
				ttl = min(ttl, linterUnenrichedCacheTTL)
			}
		}
		if time.Since(snap.loadedAt) < ttl {
			return snap, nil
		}
	}

	ch := idx.triggerRefresh(ctx)
	select {
	case <-ctx.Done():
		if snap != nil {
			return snap, nil
		}

		return nil, ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			if snap != nil {
				logger.WarnContext(ctx, "serving stale linter snapshot after refresh error", slog.Any("error", res.Err))
				return snap, nil
			}

			return nil, res.Err
		}
		snapOut, _ := res.Val.(*linterSnapshot)

		return snapOut, nil
	}
}

func parseSourceResultJSON(data []byte) (map[string][]LinterFindingDetail, error) {
	var raw map[string][]LinterFindingDetail
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	byBug := make(map[string][]LinterFindingDetail, len(raw))
	for filePath, list := range raw {
		if len(list) == 0 {
			continue
		}
		base := path.Base(filePath)
		bugID := strings.TrimSuffix(base, path.Ext(base))
		if bugID == "" {
			continue
		}
		for i, f := range list {
			code := f.Code
			if code == "" {
				code = "UNKNOWN"
			}
			list[i] = LinterFindingDetail{
				Code:    internStr(code),
				Message: internStr(f.Message),
			}
		}
		id := strings.Clone(bugID)
		if existing, ok := byBug[id]; ok {
			byBug[id] = append(existing, list...)
		} else {
			byBug[id] = list
		}
	}

	return byBug, nil
}

func (idx *linterIndex) refresh(ctx context.Context) (*linterSnapshot, error) {
	infos, err := idx.linterStore.ListSourceInfos(ctx)
	if err != nil {
		return nil, err
	}

	sourceSet := make(map[string]struct{}, len(infos)+48)
	for _, info := range infos {
		sourceSet[info.Source] = struct{}{}
	}
	repoIterFailed := false
	if idx.sourceRepoStore != nil {
		for repo, repoErr := range idx.sourceRepoStore.All(ctx) {
			if repoErr != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				logger.WarnContext(ctx, "linter index: failed iterating SourceRepository", slog.Any("error", repoErr))
				repoIterFailed = true

				break
			}
			if repo != nil && repo.Name != "" {
				sourceSet[repo.Name] = struct{}{}
			}
		}
	}

	idx.mu.Lock()
	if repoIterFailed {
		for _, s := range idx.knownSources {
			sourceSet[s] = struct{}{}
		}
	}
	prevCache := maps.Clone(idx.sourceCache)
	idx.mu.Unlock()

	var toFetch []models.LinterSourceInfo
	nextCache := make(map[string]cachedSourceFindings, len(infos))
	anyChanged := len(infos) != len(prevCache)

	for _, info := range infos {
		prev, ok := prevCache[info.Source]
		if ok && info.Generation > 0 && prev.generation == info.Generation && prev.updated.Equal(info.Updated) {
			nextCache[info.Source] = prev
		} else {
			toFetch = append(toFetch, info)
			anyChanged = true
		}
	}

	if len(toFetch) > 0 {
		var fetchMu sync.Mutex
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(linterFetchConcurrency)

		for _, info := range toFetch {
			g.Go(func() error {
				raw, getErr := idx.linterStore.GetFindings(gCtx, info.Source)
				if errors.Is(getErr, models.ErrNotFound) {
					return nil
				}
				if getErr != nil {
					if gCtx.Err() != nil {
						return gCtx.Err()
					}
					logger.WarnContext(gCtx, "linter index: failed fetching source findings",
						slog.String("source", info.Source), slog.Any("error", getErr))
					if prev, ok := prevCache[info.Source]; ok {
						fetchMu.Lock()
						nextCache[info.Source] = prev
						fetchMu.Unlock()
					}

					return nil
				}
				bugs, parseErr := parseSourceResultJSON(raw)
				if parseErr != nil {
					logger.WarnContext(gCtx, "linter index: failed parsing source findings JSON",
						slog.String("source", info.Source), slog.Any("error", parseErr))
					if prev, ok := prevCache[info.Source]; ok {
						fetchMu.Lock()
						nextCache[info.Source] = prev
						fetchMu.Unlock()
					}

					return nil
				}
				fetchMu.Lock()
				nextCache[info.Source] = cachedSourceFindings{
					updated:    info.Updated,
					generation: info.Generation,
					bugs:       bugs,
				}
				fetchMu.Unlock()

				return nil
			})
		}
		if waitErr := g.Wait(); waitErr != nil {
			return nil, waitErr
		}
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	knownSources := slices.Sorted(maps.Keys(sourceSet))

	idx.mu.Lock()
	sourcesChanged := !slices.Equal(knownSources, idx.knownSources)
	idx.sourceCache = nextCache
	idx.knownSources = knownSources
	tsReady := idx.timestampsReady
	var waitCh chan struct{}
	if idx.importFindingsStore != nil && (!tsReady || anyChanged || time.Since(idx.timestampsUpdated) > linterTimestampRefresh) {
		waitCh = idx.startTimestampEnrichmentLocked(ctx)
	}
	idx.mu.Unlock()

	if waitCh != nil && !tsReady {
		select {
		case <-waitCh:
			if enriched := idx.snapshot.Load(); enriched != nil {
				return enriched, nil
			}
		case <-time.After(linterColdGraceWait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	if prev := idx.snapshot.Load(); prev != nil && !anyChanged && !sourcesChanged && prev.timestampsReady == idx.timestampsReady {
		updated := *prev
		updated.loadedAt = time.Now()
		idx.snapshot.Store(&updated)

		return &updated, nil
	}

	return idx.rebuildLocked(), nil
}

func (idx *linterIndex) startTimestampEnrichmentLocked(ctx context.Context) chan struct{} {
	if idx.enriching {
		return idx.enrichDone
	}
	idx.enriching = true
	done := make(chan struct{})
	idx.enrichDone = done
	baseCtx := context.WithoutCancel(ctx)

	go func() {
		defer func() {
			idx.mu.Lock()
			idx.enriching = false
			close(done)
			idx.mu.Unlock()
		}()

		enrichCtx, cancel := context.WithTimeout(baseCtx, linterEnrichTimeout)
		defer cancel()

		allFindings, err := idx.importFindingsStore.ListAll(enrichCtx)
		if err != nil {
			logger.WarnContext(enrichCtx, "linter index: failed loading ImportFindings timestamps", slog.Any("error", err))
			return
		}

		newTS := make(map[string]int64, len(allFindings))
		for _, f := range allFindings {
			if f == nil || f.BugID == "" || f.LastAttempt.IsZero() {
				continue
			}
			newTS[f.BugID] = f.LastAttempt.Unix()
		}

		idx.mu.Lock()
		idx.timestamps = newTS
		idx.timestampsReady = true
		idx.timestampsUpdated = time.Now()
		idx.rebuildLocked()
		idx.mu.Unlock()
	}()

	return done
}

func buildLinterSnapshot(
	knownSources []string,
	sourceCache map[string]cachedSourceFindings,
	timestamps map[string]int64,
	timestampsReady bool,
) *linterSnapshot {
	sourceSet := make(map[string]struct{}, len(knownSources)+len(sourceCache))
	for _, s := range knownSources {
		if s != "" {
			sourceSet[internStr(s)] = struct{}{}
		}
	}
	for s := range sourceCache {
		if s != "" {
			sourceSet[internStr(s)] = struct{}{}
		}
	}
	sources := slices.Sorted(maps.Keys(sourceSet))

	codeSet := make(map[string]struct{}, 16)
	totalBugs := 0
	hasGenerations := false
	for _, srcData := range sourceCache {
		if srcData.generation > 0 {
			hasGenerations = true
		}
		totalBugs += len(srcData.bugs)
		for _, list := range srcData.bugs {
			for _, f := range list {
				codeSet[f.Code] = struct{}{}
			}
		}
	}
	rules := slices.Sorted(maps.Keys(codeSet))

	issues := make([]linterIssue, 0, totalBugs)
	for _, srcName := range slices.Sorted(maps.Keys(sourceCache)) {
		srcData := sourceCache[srcName]
		internedSrc := internStr(srcName)
		var fallbackUnix int64
		if !srcData.updated.IsZero() {
			fallbackUnix = srcData.updated.Unix()
		}

		for bugID, list := range srcData.bugs {
			seenCodes := make([]string, 0, len(list))
			for _, f := range list {
				if !slices.Contains(seenCodes, f.Code) {
					seenCodes = append(seenCodes, f.Code)
				}
			}
			slices.Sort(seenCodes)

			laUnix := timestamps[bugID]
			if laUnix == 0 {
				laUnix = fallbackUnix
			}

			issues = append(issues, linterIssue{
				bugID:       bugID,
				bugIDLower:  strings.ToLower(bugID),
				source:      internedSrc,
				codes:       seenCodes,
				lastAttempt: laUnix,
				findings:    list,
			})
		}
	}

	slices.SortFunc(issues, func(a, b linterIssue) int {
		return cmp.Or(
			cmp.Compare(b.lastAttempt, a.lastAttempt),
			cmp.Compare(a.bugID, b.bugID),
		)
	})

	return &linterSnapshot{
		loadedAt:        time.Now(),
		hasGenerations:  hasGenerations,
		timestampsReady: timestampsReady,
		sources:         sources,
		rules:           rules,
		issues:          issues,
	}
}

func formatUnixRFC3339(sec int64) string {
	if sec <= 0 {
		return ""
	}

	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func issueToSummary(issue linterIssue) LinterIssueSummary {
	return LinterIssueSummary{
		BugID:       issue.bugID,
		Source:      issue.source,
		Codes:       issue.codes,
		LastAttempt: formatUnixRFC3339(issue.lastAttempt),
		Details:     issue.findings,
	}
}

func (snap *linterSnapshot) query(params linterQueryParams) LinterQueryResponse {
	pageSize := min(max(params.PageSize, 0), maxLinterPageSize)
	if pageSize == 0 {
		pageSize = defaultLinterPageSize
	}
	page := max(params.Page, 1)

	targetSource := strings.TrimSpace(params.Source)
	targetCode := strings.ToUpper(strings.TrimSpace(params.Code))
	qLower := strings.ToLower(strings.TrimSpace(params.Query))

	sourceCounts := make(map[string]int, len(snap.sources))
	ruleCounts := make(map[string]int, len(snap.rules))
	totalForSources := 0
	totalForRules := 0
	var matched []int

	for i, issue := range snap.issues {
		if qLower != "" && !strings.Contains(issue.bugIDLower, qLower) {
			continue
		}

		srcMatch := targetSource == "" || issue.source == targetSource
		ruleMatch := targetCode == "" || slices.Contains(issue.codes, targetCode)

		if ruleMatch {
			sourceCounts[issue.source]++
			totalForSources++
		}
		if srcMatch {
			totalForRules++
			for _, c := range issue.codes {
				ruleCounts[c]++
			}
		}
		if srcMatch && ruleMatch {
			matched = append(matched, i)
		}
	}

	if strings.EqualFold(params.Order, "asc") {
		slices.SortFunc(matched, func(ia, ib int) int {
			a, b := snap.issues[ia], snap.issues[ib]
			return cmp.Or(
				cmp.Compare(a.lastAttempt, b.lastAttempt),
				cmp.Compare(a.bugID, b.bugID),
			)
		})
	}

	total := len(matched)
	page = min(page, max((total+pageSize-1)/pageSize, 1))
	start := (page - 1) * pageSize
	end := min(start+pageSize, total)

	pageIssues := make([]LinterIssueSummary, max(end-start, 0))
	for i, idx := range matched[start:end] {
		pageIssues[i] = issueToSummary(snap.issues[idx])
	}

	sourceFacets := make([]LinterSourceFacet, len(snap.sources))
	for i, name := range snap.sources {
		sourceFacets[i] = LinterSourceFacet{Name: name, Count: sourceCounts[name]}
	}
	ruleFacets := make([]LinterRuleFacet, len(snap.rules))
	for i, code := range snap.rules {
		ruleFacets[i] = LinterRuleFacet{Code: code, Label: ruleLabel(code), Count: ruleCounts[code]}
	}

	return LinterQueryResponse{
		Issues:   pageIssues,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
		Facets: LinterFacets{
			TotalForSources: totalForSources,
			Sources:         sourceFacets,
			TotalForRules:   totalForRules,
			Rules:           ruleFacets,
		},
	}
}
