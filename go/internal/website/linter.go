package website

import (
	"encoding/json"
	"net/http"
)

// handleLinterPage handles serving the linter findings UI page.
func (s *Server) handleLinterPage(w http.ResponseWriter, r *http.Request) {
	data := LinterPageData{
		BasePageData: BasePageData{
			ActiveSection: "linter",
		},
	}

	s.render(w, r, "linter.html", http.StatusOK, data)
}

// handleLinterSources handles listing sources that have linter findings from GCS.
func (s *Server) handleLinterSources(w http.ResponseWriter, _ *http.Request) {
	// TODO: List prefixes in GCS bucket osv-test-public-import-logs under linter-result/
	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(w).Encode([]string{"ghsa", "cve-osv", "malicious-packages"})
}

// handleLinterFindings handles fetching linter findings JSON for a specific source from GCS.
func (s *Server) handleLinterFindings(w http.ResponseWriter, r *http.Request) {
	source := r.PathValue("source")
	if source == "" {
		http.NotFound(w, r)

		return
	}

	// TODO: Download linter-result/<source>/result.json from GCS bucket
	w.Header().Set("Content-Type", "application/json")
	//nolint:errchkjson
	_ = json.NewEncoder(w).Encode(map[string][]map[string]string{
		"path/OSV-1234-5678.json": {{
			"Code":    "SCH:001",
			"Message": "record is bad",
		}}})
}
