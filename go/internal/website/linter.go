package website

import (
	"fmt"
	"net/http"
)

// handleLinterPage handles serving the linter findings UI page.
func (s *Server) handleLinterPage(w http.ResponseWriter, _ *http.Request) {
	// TODO: Serve linter UI page / template
	http.Error(w, "Linter UI page stub", http.StatusNotImplemented)
}

// handleLinterSources handles listing sources that have linter findings from GCS.
func (s *Server) handleLinterSources(w http.ResponseWriter, _ *http.Request) {
	// TODO: List prefixes in GCS bucket osv-test-public-import-logs under linter-result/
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, `{"error": "Linter sources handler stub"}`, http.StatusNotImplemented)
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
	http.Error(w, fmt.Sprintf(`{"error": "Linter findings handler stub", "source": %q}`, source), http.StatusNotImplemented)
}
