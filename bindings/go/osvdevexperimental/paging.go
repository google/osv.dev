package osvdevexperimental

import (
	"context"
	"errors"

	"osv.dev/bindings/go/osvdev"
)

// QueryPaging performs a single query with the given OSVClient, and handles
// paging logic to return all results.
func QueryPaging(ctx context.Context, c *osvdev.OSVClient, query *osvdev.Query) (*osvdev.Response, error) {
	queryResponse, err := c.Query(ctx, query)

	if err != nil {
		return nil, err
	}
	// --- Paging logic ---
	var errToReturn error

	if queryResponse.NextPageToken == "" {
		return queryResponse, nil
	}

	if ctx.Err() != nil {
		return queryResponse, &DuringPagingError{
			PageDepth: 1,
			Inner:     ctx.Err(),
		}
	}

	newQuery := *query
	newQuery.PageToken = queryResponse.NextPageToken
	nextPageResponse, err := QueryPaging(ctx, c, &newQuery)

	if err != nil {
		var dpe *DuringPagingError
		if ok := errors.As(err, &dpe); ok && dpe != nil {
			dpe.PageDepth += 1
			errToReturn = dpe
		} else {
			errToReturn = &DuringPagingError{
				PageDepth: 1,
				Inner:     err,
			}
		}

		return queryResponse, errToReturn
	}

	queryResponse.Vulns = append(queryResponse.Vulns, nextPageResponse.Vulns...)
	queryResponse.NextPageToken = nextPageResponse.NextPageToken

	return queryResponse, errToReturn
}

// BatchQueryPaging performs a batch query with the given OSVClient, and handles
// paging logic for each query to return all results.
func BatchQueryPaging(ctx context.Context, c *osvdev.OSVClient, queries []*osvdev.Query) (*osvdev.BatchedResponse, error) {
	batchResp, err := c.QueryBatch(ctx, queries)

	if err != nil {
		return nil, err
	}
	// --- Paging logic ---
	var errToReturn error
	var nextPageQueries []*osvdev.Query
	var nextPageIndexMap []int
	for i, res := range batchResp.Results {
		if res.NextPageToken == "" {
			continue
		}

		query := *queries[i]
		query.PageToken = res.NextPageToken
		nextPageQueries = append(nextPageQueries, &query)
		nextPageIndexMap = append(nextPageIndexMap, i)
	}

	if len(nextPageQueries) > 0 {
		// If context is cancelled or deadline exceeded, return now
		if ctx.Err() != nil {
			return batchResp, &DuringPagingError{
				PageDepth: 1,
				Inner:     ctx.Err(),
			}
		}

		nextPageResp, err := BatchQueryPaging(ctx, c, nextPageQueries)
		if err != nil {
			var dpe *DuringPagingError
			if ok := errors.As(err, &dpe); ok {
				dpe.PageDepth += 1
				errToReturn = dpe
			} else {
				errToReturn = &DuringPagingError{
					PageDepth: 1,
					Inner:     err,
				}
			}
		}

		// Whether there is an error or not, if there is any data,
		// we want to save and return what we got.
		if nextPageResp != nil {
			for i, res := range nextPageResp.Results {
				batchResp.Results[nextPageIndexMap[i]].Vulns = append(batchResp.Results[nextPageIndexMap[i]].Vulns, res.Vulns...)
				// Set next page token so caller knows whether this is all of the results
				// even if it is being cancelled.
				batchResp.Results[nextPageIndexMap[i]].NextPageToken = res.NextPageToken
			}
		}
	}

	return batchResp, errToReturn
}
