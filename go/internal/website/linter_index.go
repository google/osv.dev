package website

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"maps"
	"math"
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
	defaultLinterCacheTTL    = 2 * time.Minute
	linterUnenrichedCacheTTL = 15 * time.Second
	linterBackgroundRefresh  = 90 * time.Second
	linterRefreshTimeout     = 2 * time.Minute
	linterTimestampRefresh   = 30 * time.Minute
	linterColdGraceWait      = 150 * time.Millisecond
	linterEnrichTimeout      = 10 * time.Minute
	linterFetchConcurrency   = 16
	defaultLinterPageSize    = 25
	maxLinterPageSize        = 100
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

var knownCategoryLabels = map[string]string{
	"SCH":    "Schema",
	"REC":    "Record",
	"RNG":    "Range",
	"PKG":    "Package",
	"COMMIT": "Commit",
	"CVE":    "CVE",
	"DEL":    "Deleted",
	"OTHER":  "Other",
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
	FirstSeen   string                `json:"first_seen,omitempty"`
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
	Code     string `json:"code"`
	Category string `json:"category"`
	Label    string `json:"label"`
	Count    int    `json:"count"`
}

// LinterCategoryFacet holds metadata and dynamic issue count for a rule category.
type LinterCategoryFacet struct {
	Code  string `json:"code"`
	Label string `json:"label"`
	Count int    `json:"count"`
}

// LinterFacets holds dynamic facet counts across sources, rules, and categories.
type LinterFacets struct {
	TotalForSources int                   `json:"total_for_sources"`
	Sources         []LinterSourceFacet   `json:"sources"`
	TotalForRules   int                   `json:"total_for_rules"`
	Rules           []LinterRuleFacet     `json:"rules"`
	Categories      []LinterCategoryFacet `json:"categories"`
}

// LinterQueryResponse is the JSON payload returned by GET /linter-findings/query.
type LinterQueryResponse struct {
	Issues          []LinterIssueSummary `json:"issues"`
	Total           int                  `json:"total"`
	Page            int                  `json:"page"`
	PageSize        int                  `json:"page_size"`
	TimestampsReady bool                 `json:"timestamps_ready"`
	Facets          LinterFacets         `json:"facets"`
}

type linterQueryParams struct {
	Sources    []string
	SourceMode string // "include" (default) or "exclude"
	Codes      []string
	Categories []string
	RuleMode   string // "include" (default) or "exclude"
	Query      string
	Since      string // "", "24h", "7d", "30d", "90d", or "YYYY-MM-DD"
	Sort       string // "last_attempt" (default), "first_seen", "bug_id", "finding_count"
	Order      string // "desc" (default) or "asc"
	Page       int
	PageSize   int
}

// cachedFinding stores canonical string handles directly so Go's GC keeps the
// interned string boxes alive across refreshes while avoiding per-query lowercase allocations.
type cachedFinding struct {
	code         unique.Handle[string]
	message      unique.Handle[string]
	messageLower unique.Handle[string]
}

type linterIssue struct {
	bugID       string
	bugIDLower  string
	source      unique.Handle[string]
	codes       []unique.Handle[string]
	firstSeen   int64
	lastAttempt int64
	findings    []cachedFinding
}

type linterSnapshot struct {
	loadedAt        time.Time
	timestampsReady bool
	sources         []unique.Handle[string]
	rules           []unique.Handle[string]
	issues          []linterIssue // Pre-sorted by (lastAttempt DESC, bugID ASC)
	ascOrder        []int32       // Pre-computed indices for (lastAttempt ASC, bugID ASC)
	defaultFacets   LinterFacets
}

type cachedSourceFindings struct {
	updated    time.Time
	generation int64
	bugs       map[string][]cachedFinding
}

type linterIndex struct {
	linterStore         models.LinterStore
	sourceRepoStore     models.SourceRepositoryStore
	importFindingsStore models.ImportFindingsStore
	cacheTTL            time.Duration

	stopOnce sync.Once
	stopCh   chan struct{}

	snapshot atomic.Pointer[linterSnapshot]
	sf       singleflight.Group

	mu                sync.Mutex
	sourceCache       map[string]cachedSourceFindings
	knownSources      []string
	timestamps        map[string]int64
	firstSeen         map[string]int64
	timestampsUpdated time.Time
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
		stopCh:              make(chan struct{}),
		sourceCache:         make(map[string]cachedSourceFindings),
	}
}

func (idx *linterIndex) stop() {
	idx.stopOnce.Do(func() {
		close(idx.stopCh)
	})
}

// backgroundContext detaches from individual HTTP request cancellations while still
// cancelling promptly when idx.stop() is called on server shutdown or timeout elapses.
func (idx *linterIndex) backgroundContext(ctx context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	bgCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
	select {
	case <-idx.stopCh:
		cancel()
		return bgCtx, cancel
	default:
	}

	done := make(chan struct{})
	go func() {
		select {
		case <-idx.stopCh:
			cancel()
		case <-bgCtx.Done():
		case <-done:
		}
	}()

	return bgCtx, func() {
		close(done)
		cancel()
	}
}

func ruleCategory(code string) string {
	prefix, _, ok := strings.Cut(code, ":")
	if !ok || prefix == "" {
		return "OTHER"
	}

	return strings.ToUpper(prefix)
}

func categoryLabel(cat string) string {
	return cmp.Or(knownCategoryLabels[cat], cat)
}

func ruleLabel(code string) string {
	return cmp.Or(knownRuleLabels[code], code)
}

func (idx *linterIndex) hasTimestampsLocked() bool {
	return idx.importFindingsStore == nil || !idx.timestampsUpdated.IsZero()
}

func (idx *linterIndex) rebuildLocked() *linterSnapshot {
	snap := buildLinterSnapshot(idx.knownSources, idx.sourceCache, idx.timestamps, idx.firstSeen, idx.hasTimestampsLocked())
	idx.snapshot.Store(snap)

	return snap
}

func (idx *linterIndex) triggerRefresh(ctx context.Context) <-chan singleflight.Result {
	return idx.sf.DoChan("refresh", func() (any, error) {
		refreshCtx, cancel := idx.backgroundContext(ctx, linterRefreshTimeout)
		defer cancel()

		return idx.refresh(refreshCtx)
	})
}

func (idx *linterIndex) getSnapshot(ctx context.Context) (*linterSnapshot, error) {
	snap := idx.snapshot.Load()
	if snap != nil {
		ttl := idx.cacheTTL
		if !snap.timestampsReady {
			ttl = min(ttl, linterUnenrichedCacheTTL)
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

func parseSourceResultJSON(data []byte) (map[string][]cachedFinding, error) {
	var raw map[string][]LinterFindingDetail
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	byBug := make(map[string][]cachedFinding, len(raw))
	for filePath, list := range raw {
		if len(list) == 0 {
			continue
		}
		base := path.Base(filePath)
		bugID := strings.TrimSuffix(base, path.Ext(base))
		if bugID == "" {
			continue
		}
		interned := make([]cachedFinding, len(list))
		for i, f := range list {
			code := cmp.Or(f.Code, "UNKNOWN")
			interned[i] = cachedFinding{
				code:         unique.Make(code),
				message:      unique.Make(f.Message),
				messageLower: unique.Make(strings.ToLower(f.Message)),
			}
		}
		id := strings.Clone(bugID)
		byBug[id] = append(byBug[id], interned...)
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
		if info.Source != "" {
			sourceSet[info.Source] = struct{}{}
		}
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
		if prev, ok := prevCache[info.Source]; ok {
			// Retain previous cached findings by default so transient fetch/parse errors preserve state.
			nextCache[info.Source] = prev
			if info.Generation > 0 && prev.generation == info.Generation && prev.updated.Equal(info.Updated) {
				continue
			}
		}
		toFetch = append(toFetch, info)
		anyChanged = true
	}

	if len(toFetch) > 0 {
		var fetchMu sync.Mutex
		g, gCtx := errgroup.WithContext(ctx)
		g.SetLimit(linterFetchConcurrency)

		for _, info := range toFetch {
			g.Go(func() error {
				raw, getErr := idx.linterStore.GetFindings(gCtx, info.Source)
				if errors.Is(getErr, models.ErrNotFound) {
					fetchMu.Lock()
					delete(nextCache, info.Source)
					fetchMu.Unlock()

					return nil
				}
				if getErr != nil {
					if gCtx.Err() != nil {
						return gCtx.Err()
					}
					logger.WarnContext(gCtx, "linter index: failed fetching source findings",
						slog.String("source", info.Source), slog.Any("error", getErr))

					return nil
				}
				bugs, parseErr := parseSourceResultJSON(raw)
				if parseErr != nil {
					logger.WarnContext(gCtx, "linter index: failed parsing source findings JSON",
						slog.String("source", info.Source), slog.Any("error", parseErr))

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
	tsReady := idx.hasTimestampsLocked()
	shouldEnrich := idx.importFindingsStore != nil && (!tsReady || anyChanged || time.Since(idx.timestampsUpdated) > linterTimestampRefresh)
	idx.mu.Unlock()

	var waitCh <-chan singleflight.Result
	if shouldEnrich {
		waitCh = idx.triggerTimestampEnrichment(ctx)
	}

	if waitCh != nil && !tsReady {
		select {
		case res := <-waitCh:
			if res.Err == nil {
				if enriched, ok := res.Val.(*linterSnapshot); ok && enriched != nil {
					return enriched, nil
				}
			}
		case <-time.After(linterColdGraceWait):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	idx.mu.Lock()
	defer idx.mu.Unlock()

	if prev := idx.snapshot.Load(); prev != nil && !anyChanged && !sourcesChanged && prev.timestampsReady == idx.hasTimestampsLocked() {
		updated := *prev
		updated.loadedAt = time.Now()
		idx.snapshot.Store(&updated)

		return &updated, nil
	}

	return idx.rebuildLocked(), nil
}

func (idx *linterIndex) triggerTimestampEnrichment(ctx context.Context) <-chan singleflight.Result {
	return idx.sf.DoChan("timestamps", func() (any, error) {
		enrichCtx, cancel := idx.backgroundContext(ctx, linterEnrichTimeout)
		defer cancel()

		newLA, newFS, err := idx.importFindingsStore.ListTimestamps(enrichCtx)
		if err != nil {
			logger.WarnContext(enrichCtx, "linter index: failed loading ImportFindings timestamps", slog.Any("error", err))
			return nil, err
		}

		idx.mu.Lock()
		defer idx.mu.Unlock()
		idx.timestamps = newLA
		idx.firstSeen = newFS
		idx.timestampsUpdated = time.Now()

		return idx.rebuildLocked(), nil
	})
}

func addRuleAndCategoryCounts(
	codes []unique.Handle[string],
	ruleCounts map[unique.Handle[string]]int,
	catCounts map[string]int,
) {
	var seenCats []string
	for _, c := range codes {
		ruleCounts[c]++
		cat := ruleCategory(c.Value())
		if !slices.Contains(seenCats, cat) {
			seenCats = append(seenCats, cat)
			catCounts[cat]++
		}
	}
}

func buildLinterSnapshot(
	knownSources []string,
	sourceCache map[string]cachedSourceFindings,
	timestamps map[string]int64,
	firstSeen map[string]int64,
	timestampsReady bool,
) *linterSnapshot {
	sources := make([]unique.Handle[string], len(knownSources))
	for i, s := range knownSources {
		sources[i] = unique.Make(s)
	}

	codeSet := make(map[unique.Handle[string]]struct{}, 16)
	totalBugs := 0
	for _, srcData := range sourceCache {
		totalBugs += len(srcData.bugs)
		for _, list := range srcData.bugs {
			for _, f := range list {
				codeSet[f.code] = struct{}{}
			}
		}
	}
	rules := slices.Collect(maps.Keys(codeSet))
	slices.SortFunc(rules, func(a, b unique.Handle[string]) int {
		return cmp.Compare(a.Value(), b.Value())
	})

	sourceCounts := make(map[unique.Handle[string]]int, len(sources))
	ruleCounts := make(map[unique.Handle[string]]int, len(rules))
	catCounts := make(map[string]int, 8)
	issues := make([]linterIssue, 0, totalBugs)

	for _, srcName := range slices.Sorted(maps.Keys(sourceCache)) {
		srcData := sourceCache[srcName]
		srcHandle := unique.Make(srcName)
		var fallbackUnix int64
		if !srcData.updated.IsZero() {
			fallbackUnix = srcData.updated.Unix()
		}

		for bugID, list := range srcData.bugs {
			seenCodes := make([]unique.Handle[string], 0, len(list))
			for _, f := range list {
				if !slices.Contains(seenCodes, f.code) {
					seenCodes = append(seenCodes, f.code)
				}
			}
			slices.SortFunc(seenCodes, func(a, b unique.Handle[string]) int {
				return cmp.Compare(a.Value(), b.Value())
			})

			sourceCounts[srcHandle]++
			addRuleAndCategoryCounts(seenCodes, ruleCounts, catCounts)

			laUnix := timestamps[bugID]
			if laUnix == 0 {
				laUnix = fallbackUnix
			}

			issues = append(issues, linterIssue{
				bugID:       bugID,
				bugIDLower:  strings.ToLower(bugID),
				source:      srcHandle,
				codes:       seenCodes,
				firstSeen:   firstSeen[bugID],
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

	// Build ascending index order in O(N) by walking contiguous equal-timestamp blocks
	// from the end of issues (preserving ascending bugID tie-breakers within each block).
	ascOrder := make([]int32, 0, len(issues))
	for end := len(issues); end > 0; {
		start := end - 1
		for start > 0 && issues[start-1].lastAttempt == issues[end-1].lastAttempt {
			start--
		}
		for i := start; i < end; i++ {
			if i >= 0 && i <= math.MaxInt32 {
				ascOrder = append(ascOrder, int32(i))
			}
		}
		end = start
	}

	defaultFacets := buildFacets(sources, rules, sourceCounts, ruleCounts, catCounts, len(issues), len(issues))

	return &linterSnapshot{
		loadedAt:        time.Now(),
		timestampsReady: timestampsReady,
		sources:         sources,
		rules:           rules,
		issues:          issues,
		ascOrder:        ascOrder,
		defaultFacets:   defaultFacets,
	}
}

func buildFacets(
	sources []unique.Handle[string],
	rules []unique.Handle[string],
	sourceCounts map[unique.Handle[string]]int,
	ruleCounts map[unique.Handle[string]]int,
	catCounts map[string]int,
	totalForSources int,
	totalForRules int,
) LinterFacets {
	sourceFacets := make([]LinterSourceFacet, len(sources))
	for i, h := range sources {
		sourceFacets[i] = LinterSourceFacet{Name: h.Value(), Count: sourceCounts[h]}
	}
	var catNames []string
	ruleFacets := make([]LinterRuleFacet, len(rules))
	for i, h := range rules {
		code := h.Value()
		cat := ruleCategory(code)
		if !slices.Contains(catNames, cat) {
			catNames = append(catNames, cat)
		}
		ruleFacets[i] = LinterRuleFacet{Code: code, Category: cat, Label: ruleLabel(code), Count: ruleCounts[h]}
	}

	catFacets := make([]LinterCategoryFacet, len(catNames))
	for i, cat := range catNames {
		catFacets[i] = LinterCategoryFacet{Code: cat, Label: categoryLabel(cat), Count: catCounts[cat]}
	}

	return LinterFacets{
		TotalForSources: totalForSources,
		Sources:         sourceFacets,
		TotalForRules:   totalForRules,
		Rules:           ruleFacets,
		Categories:      catFacets,
	}
}

func formatUnixRFC3339(sec int64) string {
	if sec <= 0 {
		return ""
	}

	return time.Unix(sec, 0).UTC().Format(time.RFC3339)
}

func issueToSummary(issue *linterIssue) LinterIssueSummary {
	codes := make([]string, len(issue.codes))
	for i, c := range issue.codes {
		codes[i] = c.Value()
	}
	details := make([]LinterFindingDetail, len(issue.findings))
	for i, f := range issue.findings {
		details[i] = LinterFindingDetail{
			Code:    f.code.Value(),
			Message: f.message.Value(),
		}
	}

	return LinterIssueSummary{
		BugID:       issue.bugID,
		Source:      issue.source.Value(),
		Codes:       codes,
		FirstSeen:   formatUnixRFC3339(issue.firstSeen),
		LastAttempt: formatUnixRFC3339(issue.lastAttempt),
		Details:     details,
	}
}

func findHandle(handles []unique.Handle[string], target string) (unique.Handle[string], bool) {
	for _, h := range handles {
		if h.Value() == target {
			return h, true
		}
	}

	return unique.Handle[string]{}, false
}

func resolveFilterSources(sources []string, knownSources []unique.Handle[string]) []unique.Handle[string] {
	var out []unique.Handle[string]
	for _, raw := range sources {
		if trimmed := strings.TrimSpace(raw); trimmed != "" {
			if h, ok := findHandle(knownSources, trimmed); ok && !slices.Contains(out, h) {
				out = append(out, h)
			}
		}
	}

	return out
}

func resolveFilterCodes(codes, categories []string, rules []unique.Handle[string]) []unique.Handle[string] {
	codeSet := make(map[string]struct{}, len(codes))
	for _, raw := range codes {
		if norm := strings.ToUpper(strings.TrimSpace(raw)); norm != "" {
			codeSet[norm] = struct{}{}
		}
	}

	catSet := make(map[string]struct{}, len(categories))
	for _, rawCat := range categories {
		if cat := strings.ToUpper(strings.TrimSpace(rawCat)); cat != "" {
			catSet[cat] = struct{}{}
		}
	}

	var out []unique.Handle[string]
	for _, h := range rules {
		code := h.Value()
		if _, ok := codeSet[code]; ok {
			out = append(out, h)
		} else if _, ok := catSet[ruleCategory(code)]; ok {
			out = append(out, h)
		}
	}

	return out
}

func parseSinceCutoff(since string) (int64, bool) {
	since = strings.TrimSpace(since)
	if since == "" {
		return 0, false
	}
	now := time.Now()

	switch strings.ToLower(since) {
	case "24h", "1d":
		return now.Add(-24 * time.Hour).Unix(), true
	case "7d":
		return now.Add(-7 * 24 * time.Hour).Unix(), true
	case "30d":
		return now.Add(-30 * 24 * time.Hour).Unix(), true
	case "90d":
		return now.Add(-90 * 24 * time.Hour).Unix(), true
	}

	if t, err := time.Parse("2006-01-02", since); err == nil {
		return t.UTC().Unix(), true
	}

	return 0, false
}

func issueMatchesQuery(issue *linterIssue, qLower string) bool {
	if strings.Contains(issue.bugIDLower, qLower) {
		return true
	}
	for _, f := range issue.findings {
		if strings.Contains(f.messageLower.Value(), qLower) {
			return true
		}
	}

	return false
}

func compareIssuesBySort(a, b *linterIssue, sortField string, asc bool) int {
	var c int
	switch sortField {
	case "first_seen":
		if (a.firstSeen == 0) != (b.firstSeen == 0) {
			if a.firstSeen == 0 {
				return 1
			}

			return -1
		}
		c = cmp.Compare(a.firstSeen, b.firstSeen)
	case "finding_count":
		c = cmp.Compare(len(a.findings), len(b.findings))
	case "bug_id":
		c = cmp.Compare(a.bugID, b.bugID)
	default:
		c = cmp.Compare(a.lastAttempt, b.lastAttempt)
	}
	if c != 0 {
		if !asc {
			return -c
		}

		return c
	}

	return cmp.Compare(a.bugID, b.bugID)
}

func (snap *linterSnapshot) query(params linterQueryParams) LinterQueryResponse {
	pageSize := params.PageSize
	if pageSize <= 0 {
		pageSize = defaultLinterPageSize
	} else if pageSize > maxLinterPageSize {
		pageSize = maxLinterPageSize
	}
	page := max(params.Page, 1)

	sortField := strings.ToLower(strings.TrimSpace(params.Sort))
	switch sortField {
	case "first_seen", "finding_count", "bug_id":
	default:
		sortField = "last_attempt"
	}
	isAsc := strings.EqualFold(params.Order, "asc")

	hasSourceFilter := len(params.Sources) > 0
	excludeSources := strings.EqualFold(params.SourceMode, "exclude")

	hasRuleInput := len(params.Codes) > 0 || len(params.Categories) > 0
	excludeRules := strings.EqualFold(params.RuleMode, "exclude")

	qLower := strings.ToLower(strings.TrimSpace(params.Query))
	cutoffUnix, hasSince := parseSinceCutoff(params.Since)
	// Avoid filtering out all issues before background Datastore FirstSeen enrichment finishes.
	applySince := hasSince && snap.timestampsReady
	hasAnyFilter := applySince || qLower != "" || hasSourceFilter || hasRuleInput

	// O(pageSize) fast path when no filters or custom sort fields are active.
	if !hasAnyFilter && sortField == "last_attempt" {
		total := len(snap.issues)
		page = min(page, max((total+pageSize-1)/pageSize, 1))
		start := (page - 1) * pageSize
		end := min(start+pageSize, total)

		pageIssues := make([]LinterIssueSummary, 0, defaultLinterPageSize)
		for i := start; i < end; i++ {
			idx := i
			if isAsc {
				idx = int(snap.ascOrder[i])
			}
			pageIssues = append(pageIssues, issueToSummary(&snap.issues[idx]))
		}

		return LinterQueryResponse{
			Issues:          pageIssues,
			Total:           total,
			Page:            page,
			PageSize:        pageSize,
			TimestampsReady: snap.timestampsReady,
			Facets:          snap.defaultFacets,
		}
	}

	var matched []int
	var facets LinterFacets
	if !hasAnyFilter {
		matched = make([]int, 0, len(snap.issues))
		for i := range snap.issues {
			matched = append(matched, i)
		}
		facets = snap.defaultFacets
	} else {
		targetSources := resolveFilterSources(params.Sources, snap.sources)
		targetCodes := resolveFilterCodes(params.Codes, params.Categories, snap.rules)

		sourceCounts := make(map[unique.Handle[string]]int, len(snap.sources))
		ruleCounts := make(map[unique.Handle[string]]int, len(snap.rules))
		catCounts := make(map[string]int, 8)
		totalForSources := 0
		totalForRules := 0

		matchesFilter := func(issue *linterIssue) (bool, bool, bool) {
			if applySince && issue.firstSeen < cutoffUnix {
				return false, false, false
			}
			if qLower != "" && !issueMatchesQuery(issue, qLower) {
				return false, false, false
			}

			srcMatch := true
			if hasSourceFilter {
				srcMatch = slices.Contains(targetSources, issue.source) != excludeSources
			}

			ruleMatch := true
			if hasRuleInput {
				ruleMatch = slices.ContainsFunc(issue.codes, func(c unique.Handle[string]) bool {
					return slices.Contains(targetCodes, c) != excludeRules
				})
			}

			return true, srcMatch, ruleMatch
		}

		useAscOrder := sortField == "last_attempt" && isAsc
		for step := range snap.issues {
			idx := step
			if useAscOrder {
				idx = int(snap.ascOrder[step])
			}
			issue := &snap.issues[idx]
			ok, srcMatch, ruleMatch := matchesFilter(issue)
			if !ok {
				continue
			}

			if ruleMatch {
				sourceCounts[issue.source]++
				totalForSources++
			}
			if srcMatch {
				totalForRules++
				addRuleAndCategoryCounts(issue.codes, ruleCounts, catCounts)
			}
			if srcMatch && ruleMatch {
				matched = append(matched, idx)
			}
		}

		facets = buildFacets(snap.sources, snap.rules, sourceCounts, ruleCounts, catCounts, totalForSources, totalForRules)
	}

	if sortField != "last_attempt" {
		slices.SortFunc(matched, func(ia, ib int) int {
			return compareIssuesBySort(&snap.issues[ia], &snap.issues[ib], sortField, isAsc)
		})
	}

	total := len(matched)
	page = min(page, max((total+pageSize-1)/pageSize, 1))
	start := (page - 1) * pageSize
	end := min(start+pageSize, total)

	pageIssues := make([]LinterIssueSummary, 0, defaultLinterPageSize)
	for _, idx := range matched[start:end] {
		pageIssues = append(pageIssues, issueToSummary(&snap.issues[idx]))
	}

	return LinterQueryResponse{
		Issues:          pageIssues,
		Total:           total,
		Page:            page,
		PageSize:        pageSize,
		TimestampsReady: snap.timestampsReady,
		Facets:          facets,
	}
}
