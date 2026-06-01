package api

import (
	"context"
	"encoding/hex"
	"errors"
	"iter"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"github.com/google/osv.dev/go/purl"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	pb "osv.dev/bindings/go/api"
)

// startCursor is a cursor that is used to indicate the start of the query.
// (This is "FIRST_PAGE_TOKEN" encoded in base64, from the Python implementation)
const startCursor = "RklSU1RfUEFHRV9UT0tFTg=="

const (
	maxSingleQueryTimeout   = 20 * time.Second
	maxSingleQueryResponses = 3000
)

func (s *server) QueryAffected(ctx context.Context, params *pb.QueryAffectedParameters) (*pb.VulnerabilityList, error) {
	queryInfo, err := s.parseQuery(params.GetQuery())
	// Log some info about the query
	var logFields []any
	if err != nil {
		logFields = append(logFields, slog.String("type", "invalid"))
	} else {
		if queryInfo.commit != "" {
			logFields = append(logFields, slog.String("type", "commit"))
		} else {
			if queryInfo.fromPURL {
				logFields = append(logFields, slog.String("type", "purl"))
			} else {
				logFields = append(logFields, slog.String("type", "ecosystem"))
			}
			logFields = append(logFields, slog.String("ecosystem", queryInfo.ecosystem), slog.Bool("versioned", queryInfo.version != ""))
		}
	}
	logger.InfoContext(ctx, "QueryAffected", logFields...)
	if s.verboseLogs {
		logger.InfoContext(ctx, "full query", slog.Any("query", params.GetQuery()))
	}

	if errors.Is(err, purl.ErrUnknownPURL) {
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

	vulns, nextToken, err := s.queryAndHydrate(ctx, queryInfo, maxSingleQueryResponses, maxSingleQueryTimeout, s.vulnStore.Get)
	if err != nil {
		return nil, err
	}

	return &pb.VulnerabilityList{
		Vulns:         vulns,
		NextPageToken: nextToken,
	}, nil
}

func (s *server) QueryAffectedBatch(ctx context.Context, params *pb.QueryAffectedBatchParameters) (*pb.BatchVulnerabilityList, error) {
	return nil, nil
}

type parsedQueryInfo struct {
	commit      string
	ecosystem   string
	packageName string
	version     string
	fromPURL    bool // just for logging purposes
	pageToken   string
}

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

func (s *server) queryAndHydrate(ctx context.Context, qi parsedQueryInfo, limit int, timeout time.Duration, hydrate hydrateFunc) ([]*osvschema.Vulnerability, string, error) {
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	resultIDs := make(chan matchVuln)
	startTok := qi.pageToken
	if startTok == startCursor {
		startTok = ""
	}
	var matcher func(context.Context) iter.Seq2[models.MatchResult, error]
	if qi.commit != "" {
		commit, err := hex.DecodeString(qi.commit)
		if err != nil {
			return nil, "", status.Error(codes.InvalidArgument, "invalid hash")
		}
		matcher = func(ctx context.Context) iter.Seq2[models.MatchResult, error] {
			return s.vulnStore.MatchCommits(ctx, commit, startTok)
		}
	} else if qi.packageName != "" {
		matcher = func(ctx context.Context) iter.Seq2[models.MatchResult, error] {
			return s.vulnStore.MatchPackages(ctx, qi.ecosystem, qi.packageName, qi.version, startTok)
		}
	} else {
		return nil, "", status.Error(codes.InvalidArgument, "invalid query")
	}
	pageToken := func() string { return qi.pageToken }
	if qi.pageToken == "" {
		pageToken = func() string { return startCursor }
	}
	// Only do the timeout on the matcher, not on the hydrated results
	matcherCtx, timeoutCancel := context.WithTimeout(ctx, timeout)
	defer timeoutCancel()
	go func() {
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
			pageToken = match.Cursor
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
		// We finished the entire query
		pageToken = func() string { return "" }
	}()
	hydrated := make(chan hydratedResult)
	var wg sync.WaitGroup
	for range 20 {
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

	unordered := make([]hydratedResult, 0, limit)
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
	}

	// If we got a real error, fail the whole query.
	if err := context.Cause(ctx); err != nil {
		if s.verboseLogs {
			logger.ErrorContext(ctx, "failed to query and hydrate", slog.Any("error", err))
		}
		if errors.Is(err, models.ErrInvalidCursor) {
			return nil, "", status.Error(codes.InvalidArgument, "invalid cursor")
		}

		return nil, "", status.Error(codes.Internal, err.Error())
	}

	slices.SortFunc(unordered, func(a, b hydratedResult) int {
		return a.index - b.index
	})
	vulns := make([]*osvschema.Vulnerability, 0, len(unordered))
	for _, res := range unordered {
		vulns = append(vulns, res.v)
	}

	return vulns, pageToken(), nil
}
