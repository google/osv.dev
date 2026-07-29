package website

import (
	"fmt"
	"net/http"
)

// handleSearchSuggestions handles auto-complete search suggestions querying Datastore models.
// Query parameters:
//   - q: search query string / prefix
//   - ecosystem: optional ecosystem filter
func (s *Server) handleSearchSuggestions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	ecosystem := r.URL.Query().Get("ecosystem")

	// TODO: Perform prefix / search matching on Datastore vulnerability indices
	w.Header().Set("Content-Type", "application/json")
	http.Error(w, fmt.Sprintf(`{"error": "Search suggestions handler stub", "q": %q, "ecosystem": %q}`, q, ecosystem), http.StatusNotImplemented)
}
