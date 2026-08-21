package website

import (
	"encoding/json"
	"net/http"

	"github.com/google/osv.dev/go/logger"
)

const maxSearchSuggestions = 10

type searchSuggestionsResponse struct {
	Suggestions []string `json:"suggestions"`
}

// handleSearchSuggestions handles auto-complete search suggestions querying Datastore models.
// Query parameters:
//   - q: search query string / prefix
func (s *Server) handleSearchSuggestions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	suggestions, err := s.stores.VulnSearch.Autocomplete(r.Context(), q, maxSearchSuggestions)
	if err != nil {
		logger.ErrorContext(r.Context(), "failed to get search suggestions", "error", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)

		return
	}

	if suggestions == nil {
		suggestions = []string{}
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(searchSuggestionsResponse{Suggestions: suggestions}); err != nil {
		logger.ErrorContext(r.Context(), "failed to encode search suggestions", "error", err)
	}
}
