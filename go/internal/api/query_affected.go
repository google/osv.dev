package api

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/internal/osvutil/schema"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	pb "osv.dev/bindings/go/api"
)

// startCursor is a cursor that is used to indicate the start of the query.
// It's returned if the server responds before a query has even started to
// prevent a client assuming an empty page token means "we have no more results".
// (This is "FIRST_PAGE_TOKEN" encoded in base64, from the Python implementation)
const startCursor = "RklSU1RfUEFHRV9UT0tFTg=="

const (
	maxSingleQueryTimeout   = 20 * time.Second
	maxSingleQueryResponses = 3000
	maxBatchQueries         = 1000
	maxBatchQueryTimeout    = 35 * time.Second
	maxBatchQueryResponses  = 1000
	numParallelHydration    = 20

	// Soft limit on response size - this is just to signal to stop matching,
	// so it can be exceeded by quite a lot (so we use a relatively conservative number).
	// ESPv2 has a limit of ~100MiB on response sizes.
	responseSizeBytesSoftLimit = 10_000_000 // 10MB
)

func (s *server) QueryAffected(ctx context.Context, params *pb.QueryAffectedParameters) (*pb.VulnerabilityList, error) {
	queryInfo, err := s.parseQuery(params.GetQuery())
	s.logQueryInfo(ctx, queryInfo, err != nil)
	if s.verboseLogs {
		logger.InfoContext(ctx, "full query", slog.Any("query", params.GetQuery()))
	}

	if errors.Is(err, purl.ErrUnknownPURL) {
		// TODO(michaelkedar): https://github.com/google/osv.dev/issues/5523
		// All unsupported PURL queries would simply return a 200
		// status code with an empty response.
		// To avoid breaking existing behavior,
		// we return an empty response here with no error.
		// This needs to be revisited with a more considerate design.
		return &pb.VulnerabilityList{}, nil
	}
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	estimatedSizeBytes := new(atomic.Int64)
	vulns, nextToken, err := s.queryAndHydrate(ctx, queryInfo, maxSingleQueryResponses, s.getSingleQueryTimeout(), s.vulnStore.GetFull, estimatedSizeBytes)
	if err != nil {
		return nil, err
	}
	if s.verboseLogs {
		logger.InfoContext(ctx, "queryAndHydrate completed successfully",
			slog.Int("count", len(vulns)),
			slog.Int64("estimated_size", estimatedSizeBytes.Load()))
	}

	return &pb.VulnerabilityList{
		Vulns:         vulns,
		NextPageToken: nextToken,
	}, nil
}

// logQueryInfo logs some basic info about a query.
// It logs only the ecosystem and not any specific package name or version
// to avoid logging potentially identifiable information about users.
func (s *server) logQueryInfo(ctx context.Context, queryInfo parsedQueryInfo, isInvalid bool) {
	var logFields []any
	queryType := "invalid"
	if !isInvalid {
		if queryInfo.commit != "" {
			queryType = "commit"
		} else {
			if queryInfo.fromPURL {
				queryType = "purl"
			} else {
				queryType = "ecosystem"
			}
			logFields = append(logFields, slog.String("ecosystem", queryInfo.ecosystem), slog.Bool("versioned", queryInfo.version != ""))
		}
	}
	logFields = append(logFields, slog.String("type", queryType))
	logger.InfoContext(ctx, "QueryAffected", logFields...)
}

func (s *server) QueryAffectedBatch(ctx context.Context, params *pb.QueryAffectedBatchParameters) (*pb.BatchVulnerabilityList, error) {
	// collect the queryInfo for each query
	firstErr := ""
	queries := params.GetQuery().GetQueries()
	queryInfos := make([]*parsedQueryInfo, len(queries))
	for i, query := range queries {
		info, err := s.parseQuery(query)
		if errors.Is(err, purl.ErrUnknownPURL) {
			// TODO(michaelkedar): https://github.com/google/osv.dev/issues/5523
			// All unsupported PURL queries would simply return a 200
			// status code with an empty response.
			// To avoid breaking existing behavior,
			// we return an empty response here with no error.
			// This needs to be revisited with a more considerate design.
			queryInfos[i] = nil

			continue
		}
		if err != nil {
			if firstErr == "" {
				firstErr = fmt.Sprintf("error in query at index %d: %s", i, err.Error())
			}
			queryInfos[i] = nil

			continue
		}
		queryInfos[i] = &info
	}

	s.logBatchQueryInfo(ctx, queryInfos)
	if s.verboseLogs {
		logger.InfoContext(ctx, "full batch query", slog.Any("query", params.GetQuery()))
	}
	if len(queryInfos) > maxBatchQueries {
		return nil, status.Error(codes.InvalidArgument, "too many queries")
	}
	if firstErr != "" {
		return nil, status.Error(codes.InvalidArgument, firstErr)
	}

	estimatedSizeBytes := new(atomic.Int64)
	hydrate := func(ctx context.Context, id string) (*osvschema.Vulnerability, error) {
		modified, err := s.vulnStore.GetModified(ctx, id)
		if err != nil {
			return nil, err
		}

		return &osvschema.Vulnerability{Id: id, Modified: timestamppb.New(modified)}, nil
	}

	type queryAndHydrateResult struct {
		idx       int
		vulns     []*osvschema.Vulnerability
		nextToken string
		err       error
	}

	// Create a channel to receive the results from the goroutines.
	resultsChan := make(chan *queryAndHydrateResult)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for i, query := range queryInfos {
		go func() {
			if query == nil {
				// handling unknown PURL types
				resultsChan <- &queryAndHydrateResult{
					idx:       i,
					vulns:     []*osvschema.Vulnerability{},
					nextToken: "",
					err:       nil,
				}

				return
			}
			vulns, nextToken, err := s.queryAndHydrate(ctx, *query, maxBatchQueryResponses, s.getBatchQueryTimeout(), hydrate, estimatedSizeBytes)
			resultsChan <- &queryAndHydrateResult{
				idx:       i,
				vulns:     vulns,
				nextToken: nextToken,
				err:       err,
			}
		}()
	}

	list := &pb.BatchVulnerabilityList{}
	list.Results = make([]*pb.VulnerabilityList, len(queryInfos))

	var firstHydrateErr error
	for range queryInfos {
		result := <-resultsChan
		if result.err != nil {
			if firstHydrateErr == nil {
				firstHydrateErr = fmt.Errorf("error in query at index %d: %w", result.idx, result.err)
				cancel()
			}
			// we need to continue to drain the channel
			continue
		}
		list.Results[result.idx] = &pb.VulnerabilityList{
			Vulns:         result.vulns,
			NextPageToken: result.nextToken,
		}
	}

	if firstHydrateErr != nil {
		return nil, firstHydrateErr
	}

	if s.verboseLogs {
		logger.InfoContext(ctx, "batch queryAndHydrate completed successfully",
			slog.Int64("estimated_size", estimatedSizeBytes.Load()))
	}

	return list, nil
}

// logBatchQueryInfo logs some basic info about a batch query.
// It logs only the ecosystems and not any specific package names or versions
// to avoid logging potentially identifiable information about users.
func (s *server) logBatchQueryInfo(ctx context.Context, queryInfos []*parsedQueryInfo) {
	commitQueries := 0
	purlQueries := 0
	invalidQueries := 0
	ecosystemQueries := make(map[string]int)
	for _, qi := range queryInfos {
		if qi == nil {
			invalidQueries++

			continue
		}
		if qi.commit != "" {
			commitQueries++
		} else {
			if qi.fromPURL {
				purlQueries++
			} else {
				ecosystemQueries[qi.ecosystem]++
			}
		}
	}

	ecoGroups := make([]any, 0, len(ecosystemQueries))
	for ecosystem, count := range ecosystemQueries {
		ecoGroups = append(ecoGroups, slog.Int(ecosystem, count))
	}
	logger.InfoContext(ctx, "QueryAffectedBatch",
		slog.Int("commit", commitQueries),
		slog.Group("ecosystem", ecoGroups...),
		slog.Int("purl", purlQueries),
		slog.Int("invalid", invalidQueries))
}

func (s *server) getSingleQueryTimeout() time.Duration {
	if s.singleQueryTimeout != 0 {
		return s.singleQueryTimeout
	}

	return maxSingleQueryTimeout
}

func (s *server) getBatchQueryTimeout() time.Duration {
	if s.batchQueryTimeout != 0 {
		return s.batchQueryTimeout
	}

	return maxBatchQueryTimeout
}

func (s *server) getResponseSizeLimit() int64 {
	if s.responseSizeLimit != 0 {
		return s.responseSizeLimit
	}

	return responseSizeBytesSoftLimit
}

type parsedQueryInfo struct {
	commit      string
	ecosystem   string
	packageName string
	version     string
	fromPURL    bool // just for logging purposes
	pageToken   string
}

// parseQuery parses a query and returns a parsedQueryInfo.
// It returns an error if the query is invalid.
// It returns purl.ErrUnknownPURL if the query is for an unsupported PURL type.
func (s *server) parseQuery(query *pb.Query) (parsedQueryInfo, error) {
	if query == nil {
		return parsedQueryInfo{}, errors.New("no query provided")
	}
	tok := query.GetPageToken()
	if commitQuery, ok := query.GetParam().(*pb.Query_Commit); ok {
		return parsedQueryInfo{commit: commitQuery.Commit, pageToken: tok}, nil
	}
	var qi parsedQueryInfo
	if versionQuery, ok := query.GetParam().(*pb.Query_Version); ok {
		qi.version = versionQuery.Version
	}
	if query.GetPackage() == nil {
		return parsedQueryInfo{}, errors.New("invalid query")
	}
	qi.ecosystem = query.GetPackage().GetEcosystem()
	qi.packageName = query.GetPackage().GetName()
	qi.pageToken = tok
	if purlStr := query.GetPackage().GetPurl(); purlStr != "" {
		qi.fromPURL = true
		if qi.packageName != "" {
			return parsedQueryInfo{}, errors.New("name specified in a PURL query")
		}
		if qi.ecosystem != "" {
			return parsedQueryInfo{}, errors.New("ecosystem specified in a PURL query")
		}
		pEco, pName, pVer, err := purl.Parse(purlStr)
		if err != nil {
			return parsedQueryInfo{}, err
		}
		qi.ecosystem = pEco
		qi.packageName = pName
		if pVer != "" {
			if qi.version != "" {
				return parsedQueryInfo{}, errors.New("version specified in params and PURL query")
			}
			qi.version = pVer
		}
	}

	if qi.ecosystem != "" && !schema.IsKnownEcosystem(qi.ecosystem) && qi.ecosystem != "GIT" {
		return parsedQueryInfo{}, errors.New("invalid ecosystem")
	}

	return qi, nil
}

type hydrateFunc func(ctx context.Context, id string) (*osvschema.Vulnerability, error)

type matchVuln struct {
	id    string
	index int
}

type hydratedResult struct {
	index int
	v     *osvschema.Vulnerability
	id    string // useful for verbose logging on error
	err   error
}

// queryAndHydrate performs the actual query and hydration.
func (s *server) queryAndHydrate(
	ctx context.Context,
	qi parsedQueryInfo,
	limit int,
	timeout time.Duration,
	hydrate hydrateFunc,
	estimatedSizeBytes *atomic.Int64,
) ([]*osvschema.Vulnerability, string, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	matcher, err := s.resolveMatcher(qi)
	if err != nil {
		return nil, "", err
	}

	matchResult, matchCancel := s.runMatcher(ctx, matcher, qi.pageToken, limit, timeout, cancel)
	hydratedCh := s.hydrateParallel(ctx, matchResult.resultIDsCh, hydrate)
	vulns, err := s.collectAndSort(ctx, hydratedCh, limit, cancel, matchCancel, estimatedSizeBytes)
	if err != nil {
		return nil, "", err
	}

	return vulns, matchResult.getPageToken(), nil
}

type matcherFunc func(context.Context) iter.Seq2[models.MatchResult, error]

// resolveMatcher returns a matcher function for the given query info.
// This chooses to either query by commit or by package depending on what's in the query.
func (s *server) resolveMatcher(qi parsedQueryInfo) (matcherFunc, error) {
	startTok := qi.pageToken
	if startTok == startCursor {
		startTok = ""
	}
	if qi.commit != "" {
		commit, err := hex.DecodeString(qi.commit)
		if err != nil {
			return nil, status.Error(codes.InvalidArgument, "invalid hash")
		}

		return func(ctx context.Context) iter.Seq2[models.MatchResult, error] {
			return s.vulnStore.MatchCommits(ctx, commit, startTok)
		}, nil
	}
	if qi.packageName != "" {
		return func(ctx context.Context) iter.Seq2[models.MatchResult, error] {
			return s.vulnStore.MatchPackages(ctx, qi.ecosystem, qi.packageName, qi.version, startTok)
		}, nil
	}

	return nil, status.Error(codes.InvalidArgument, "invalid query")
}

type matcherResult struct {
	resultIDsCh  <-chan matchVuln
	getPageToken func() string
}

// runMatcher runs the matcher and returns the results over a channel, along with a function to get the next page token.
// The returned cancel function can be used to cancel the matcher.
// The getPageToken function will block until the matcher is finished.
func (s *server) runMatcher(
	ctx context.Context,
	matcher matcherFunc,
	startTok string,
	limit int,
	timeout time.Duration,
	cancel context.CancelCauseFunc,
) (matcherResult, context.CancelFunc) {
	resultIDs := make(chan matchVuln, numParallelHydration)
	done := make(chan struct{})
	currentCursor := func() string { return startTok }
	if startTok == "" {
		currentCursor = func() string { return startCursor }
	}
	matcherCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	go func() {
		defer timeoutCancel()
		defer close(done)
		defer close(resultIDs)
		idx := 0
		for match, err := range matcher(matcherCtx) {
			if err != nil {
				if errors.Is(matcherCtx.Err(), context.DeadlineExceeded) || errors.Is(matcherCtx.Err(), context.Canceled) {
					// If we timed out or been cancelled, we just return what we have.
					return
				}
				cancel(err)

				return
			}
			currentCursor = match.Cursor
			if !match.IsMatch {
				continue
			}
			select {
			case <-ctx.Done():
				return
			case resultIDs <- matchVuln{id: match.ID, index: idx}:
				idx++
				if idx >= limit {
					return
				}
			}
		}
		// We finished the entire query only if context was not cancelled
		if matcherCtx.Err() == nil {
			currentCursor = func() string { return "" }
		} else {
			logger.WarnContext(ctx, "matcher query exited early due to cancellation or timeout, preserving cursor")
		}
	}()

	return matcherResult{
		resultIDsCh: resultIDs,
		// Capturing the function lets us read the last value of the cursor after the goroutine has terminated.
		getPageToken: func() string {
			<-done // Block until matcher is finished
			return currentCursor()
		},
	}, timeoutCancel
}

// hydrateParallel hydrates the vulnerability IDs in parallel.
// It uses numParallelHydration workers to hydrate the vulnerabilities.
// Each worker pulls a vulnerability ID from the resultIDs channel and hydrates it.
// If the context is cancelled, the worker will stop.
// It returns the hydrated vulnerabilities over the hydrated channel.
func (s *server) hydrateParallel(ctx context.Context, resultIDs <-chan matchVuln, hydrate hydrateFunc) <-chan hydratedResult {
	hydrated := make(chan hydratedResult, numParallelHydration)
	var wg sync.WaitGroup
	for range numParallelHydration {
		wg.Go(func() {
			for mv := range resultIDs {
				v, err := hydrate(ctx, mv.id)
				if err != nil {
					hydrated <- hydratedResult{index: mv.index, err: err, id: mv.id}
					continue
				}
				hydrated <- hydratedResult{index: mv.index, v: v, id: mv.id}
			}
		})
	}
	go func() {
		wg.Wait()
		close(hydrated)
	}()

	return hydrated
}

// collectAndSort collects the hydrated vulnerabilities and sorts them by index.
// It calls matchCancel if the estimated response size limit is reached.
// It aborts the query if any of the vulnerabilities fail to hydrate.
// It returns the sorted vulnerabilities and an error if any.
func (s *server) collectAndSort(ctx context.Context,
	hydrated <-chan hydratedResult,
	limit int,
	cancel context.CancelCauseFunc,
	matchCancel context.CancelFunc,
	estimatedSizeBytes *atomic.Int64,
) ([]*osvschema.Vulnerability, error) {
	unordered := make([]hydratedResult, 0, limit)
	loggedSize := false
	for res := range hydrated {
		if res.err != nil {
			if errors.Is(res.err, models.ErrNotFound) {
				// TODO: publish gcs_retry message
				continue
			}
			// This is a real error, fail the whole query.
			cancel(res.err)
			if s.verboseLogs {
				logger.ErrorContext(ctx, "failed to hydrate", slog.String("id", res.id), slog.String("error", res.err.Error()))
			}
			// continue to drain the channel
			continue
		}
		unordered = append(unordered, res)
		estimatedSizeBytes.Add(int64(proto.Size(res.v)))
		if sz := estimatedSizeBytes.Load(); sz > s.getResponseSizeLimit() {
			if !loggedSize && s.verboseLogs {
				logger.InfoContext(ctx, "estimated response size limit reached", slog.Int64("estimatedSize", sz))
				loggedSize = true
			}
			matchCancel()
		}
	}

	// If we got a real error, fail the whole query.
	if err := context.Cause(ctx); err != nil {
		if s.verboseLogs {
			logger.ErrorContext(ctx, "failed to query and hydrate", slog.Any("error", err))
		}
		if errors.Is(err, models.ErrInvalidCursor) {
			return nil, status.Error(codes.InvalidArgument, "invalid cursor")
		}

		return nil, status.Error(codes.Internal, err.Error())
	}

	slices.SortFunc(unordered, func(a, b hydratedResult) int {
		return a.index - b.index
	})
	vulns := make([]*osvschema.Vulnerability, 0, len(unordered))
	for _, res := range unordered {
		vulns = append(vulns, res.v)
	}

	return vulns, nil
}
