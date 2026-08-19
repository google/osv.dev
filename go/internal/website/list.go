package website

import (
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/ossf/osv-schema/bindings/go/osvschema"
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
	isTurboFrame := r.Header.Get("Turbo-Frame") != ""

	// Redirect full-page requests (non-Turbo-Frame) that contain a page parameter back to canonical URL
	if !isTurboFrame && pageStr != "" {
		queryVals := r.URL.Query()
		queryVals.Del("page")
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

	// Stub mock data for development
	mockVulns := []ListedVulnerabilityDisplay{
		{
			ID:        "GHSA-1234-5678-90ab",
			Published: time.Now().Add(-24 * time.Hour),
			Packages: []models.Package{
				{Package: &osvschema.Package{Ecosystem: "PyPI", Name: "requests"}},
				{Package: &osvschema.Package{Ecosystem: "PyPI", Name: "urllib3"}},
			},
			Summary: "Critical remote code execution in `requests`",
			IsFixed: true,
			Severities: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
			},
		},
		{
			ID:        "CVE-2024-9999",
			Published: time.Now().Add(-48 * time.Hour),
			Packages: []models.Package{
				{Package: &osvschema.Package{Ecosystem: "Go", Name: "golang.org/x/net"}},
				{Repo: "https://github.com/golang/net"},
			},
			Summary: "Denial of service in HTTP/2 handler",
			IsFixed: false,
			Severities: []*osvschema.Severity{
				{Type: osvschema.Severity_CVSS_V3, Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"},
			},
		},
	}

	mockEcosystemCounts := []EcosystemCount{
		{Name: "PyPI", Count: 1420},
		{Name: "Go", Count: 850},
		{Name: "npm", Count: 3200},
		{Name: "Maven", Count: 1100},
		{Name: "A Very Long Ecosystem Name", Count: 1111111},
		{Name: "A Very *Very* Long Ecosystem Name (comes with snacks!)", Count: 1111111},
		{Name: "Evil PyPI", Count: 1420},
		{Name: "Evil Go", Count: 850},
		{Name: "Good npm", Count: 3200},
		{Name: "Evil Maven", Count: 1100},
	}

	totalEcosystemCount := 0
	for _, eco := range mockEcosystemCounts {
		totalEcosystemCount += eco.Count
	}

	now := time.Now()
	vulns := make([]ListedVulnerabilityDisplay, 0, vulnsPerPage)
	for i := range vulnsPerPage {
		idx := (page-1)*vulnsPerPage + i
		item := mockVulns[i%len(mockVulns)]
		item.Published = now.Add(-time.Duration(idx*3) * time.Hour)
		vulns = append(vulns, item)
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
		Page:                page,
		TotalPages:          5,
		EcosystemCounts:     mockEcosystemCounts,
		TotalEcosystemCount: totalEcosystemCount,
		Vulnerabilities:     vulns,
	}

	s.render(w, r, "list.html", http.StatusOK, &data)
}
