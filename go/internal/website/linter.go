package website

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
)

func (s *Server) redirectLinterToTest(w http.ResponseWriter, r *http.Request) bool {
	host := strings.ToLower(r.Host)
	if colonIdx := strings.IndexByte(host, ':'); colonIdx != -1 {
		host = host[:colonIdx]
	}

	if host == "osv.dev" {
		http.Redirect(w, r, "https://test.osv.dev"+r.URL.RequestURI(), http.StatusFound)

		return true
	}
	if host == "api.osv.dev" {
		http.Redirect(w, r, "https://api.test.osv.dev"+r.URL.RequestURI(), http.StatusFound)

		return true
	}

	return false
}

// handleLinterPage handles serving the linter findings UI page.
func (s *Server) handleLinterPage(w http.ResponseWriter, r *http.Request) {
	if s.redirectLinterToTest(w, r) {
		return
	}

	data := LinterPageData{
		BasePageData: BasePageData{
			ActiveSection: "linter",
		},
	}

	s.renderStandalone(w, r, "linter.html", http.StatusOK, data)
}

// handleLinterSources handles listing sources that have linter findings from GCS.
func (s *Server) handleLinterSources(w http.ResponseWriter, r *http.Request) {
	if s.redirectLinterToTest(w, r) {
		return
	}

	sources, err := s.stores.Linter.ListSources(r.Context())
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to list linter sources", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	if sources == nil {
		sources = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(sources); err != nil {
		logger.ErrorContext(r.Context(), "failed to encode linter sources", "error", err)
	}
}

// handleLinterFindings handles fetching linter findings JSON for a specific source from GCS.
func (s *Server) handleLinterFindings(w http.ResponseWriter, r *http.Request) {
	if s.redirectLinterToTest(w, r) {
		return
	}

	source := r.PathValue("source")
	if source == "" {
		http.NotFound(w, r)

		return
	}

	findings, err := s.stores.Linter.GetFindings(r.Context(), source)
	if errors.Is(err, models.ErrNotFound) {
		http.NotFound(w, r)

		return
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to get linter findings", "source", source, "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(findings); err != nil {
		logger.ErrorContext(r.Context(), "failed to write linter findings", "source", source, "error", err)
	}
}
