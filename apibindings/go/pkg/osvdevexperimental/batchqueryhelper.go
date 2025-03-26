package osvdevexperimental

import (
	"context"
	"errors"

	"github.com/google/osv.dev/apibindings/go/pkg/osvdev"
)

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

		nextPageResp, err := c.QueryBatch(ctx, nextPageQueries)
		if err != nil {
			var dpr *DuringPagingError
			if ok := errors.As(err, &dpr); ok {
				dpr.PageDepth += 1
				errToReturn = dpr
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
