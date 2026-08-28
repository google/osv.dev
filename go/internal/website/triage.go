package website

import (
	"errors"
	"net/http"
	"regexp"

	"github.com/google/osv.dev/go/internal/models"
	"github.com/google/osv.dev/go/logger"
)

var cveIDRegex = regexp.MustCompile(`^(?i)CVE-\d{4}-\d+$`)

// handleTriagePage handles serving the vulnerability triage UI page.
func (s *Server) handleTriagePage(w http.ResponseWriter, r *http.Request) {
	data := TriagePageData{
		BasePageData: BasePageData{
			ActiveSection: "triage",
		},
		Columns: []int{1, 2, 3},
	}

	s.render(w, r, "triage.html", http.StatusOK, data)
}

// handleTriageProxy handles proxying triage workflow actions from GCS buckets or external APIs.
func (s *Server) handleTriageProxy(w http.ResponseWriter, r *http.Request) {
	source := r.URL.Query().Get("source")
	vulnID := r.URL.Query().Get("id")

	if source == "" || vulnID == "" {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Missing source or id parameters",
		})

		return
	}

	if !cveIDRegex.MatchString(vulnID) {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Invalid ID format",
		})

		return
	}

	data, err := s.stores.Triage.GetFile(r.Context(), source, vulnID)
	if errors.Is(err, models.ErrInvalidArgument) {
		s.renderJSON(w, r, http.StatusBadRequest, map[string]string{
			"error": "Invalid source",
		})

		return
	}
	if errors.Is(err, models.ErrNotFound) {
		s.renderJSON(w, r, http.StatusNotFound, map[string]string{
			"error": "File not found",
		})

		return
	}
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to fetch triage file", "source", source, "id", vulnID, "error", err)
		s.renderJSON(w, r, http.StatusInternalServerError, map[string]string{
			"error": "Internal server error",
		})

		return
	}

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write(data); err != nil {
		logger.ErrorContext(r.Context(), "failed to write triage file response", "source", source, "id", vulnID, "error", err)
	}
}
