package website

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
	"golang.org/x/sync/errgroup"
)

const vulnsPerPage = 16

// handleList handles rendering the vulnerability listing page and backing paginated list queries.
// Query parameters:
//   - q: search query string
//   - ecosystem: ecosystem filter
//   - page: page number
func (s *Server) handleList(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	ecosystem := r.URL.Query().Get("ecosystem")
	pageStr := r.URL.Query().Get("page")
	afterStr := r.URL.Query().Get("after")
	isTurboFrame := r.Header.Get("Turbo-Frame") != ""

	// Redirect full-page requests (non-Turbo-Frame) that contain a page parameter back to canonical URL
	if !isTurboFrame && (pageStr != "" || afterStr != "") {
		queryVals := r.URL.Query()
		queryVals.Del("page")
		queryVals.Del("after")
		targetURL := "/list"
		if encoded := queryVals.Encode(); encoded != "" {
			targetURL += "?" + encoded
		}
		http.Redirect(w, r, targetURL, http.StatusFound)

		return
	}

	page := 1
	if p, err := strconv.Atoi(pageStr); err == nil && p > 0 {
		page = p
	}
	var afterTime time.Time
	var afterID string
	if afterStr != "" {
		timeStr, id, found := strings.Cut(afterStr, "_")
		if found {
			usec, err := strconv.ParseInt(timeStr, 10, 64)
			if err == nil {
				afterTime = time.UnixMicro(usec)
				afterID = id
			} else {
				logger.ErrorContext(r.Context(), "failed to parse after_time", "after_time", afterStr)
			}
		} else {
			logger.ErrorContext(r.Context(), "failed to parse after_time", "after_time", afterStr)
		}
	}
	if page > 1 {
		logger.WarnContext(r.Context(), "search is using legacy pagination")
	}

	g, ctx := errgroup.WithContext(r.Context())

	var vulns []ListedVulnerabilityDisplay
	var nextAfter string
	g.Go(func() error {
		result, err := s.stores.VulnSearch.Search(ctx, models.VulnerabilitySearchQuery{
			Query:     q,
			Ecosystem: ecosystem,
			AfterTime: afterTime,
			AfterID:   afterID,
			PageSize:  vulnsPerPage,
			Page:      page,
		})
		if err != nil {
			return err
		}

		vulns = make([]ListedVulnerabilityDisplay, len(result.Vulnerabilities))
		for i, v := range result.Vulnerabilities {
			vulns[i] = ListedVulnerabilityDisplay(*v)
		}
		if !result.NextAfterTime.IsZero() {
			nextAfter = fmt.Sprintf("%d_%s", result.NextAfterTime.UnixMicro(), result.NextAfterID)
		}

		return nil
	})

	var ecoCounts []EcosystemCount
	if !isTurboFrame {
		// Only need to do this for the first page load, not subsequent page loads using the Turbo frame.
		g.Go(func() error {
			counts, err := s.stores.VulnSearch.EcosystemCounts(ctx)
			if err != nil {
				return err
			}
			ecoCounts = counts

			return nil
		})
	}

	if err := g.Wait(); err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	totalEcoCounts := 0
	for _, c := range ecoCounts {
		totalEcoCounts += c.Count
	}

	pageTitle := "Vulnerability Database - OSV"
	if ecosystem != "" {
		pageTitle = ecosystem + " - OSV"
	}

	data := ListPageData{
		BasePageData: BasePageData{
			Title:             pageTitle,
			ActiveSection:     "vulnerabilities",
			DisableTurboCache: true,
		},
		Query:               q,
		SelectedEcosystem:   ecosystem,
		CurrentAfter:        afterStr,
		NextAfter:           nextAfter,
		EcosystemCounts:     ecoCounts,
		TotalEcosystemCount: totalEcoCounts,
		Vulnerabilities:     vulns,
	}

	s.render(w, r, "list.html", http.StatusOK, &data)
}
